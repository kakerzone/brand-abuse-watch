#!/usr/bin/env python3
"""Create deduplicated, evidence-rich Lark alert cards; sends only with --send."""
import argparse, base64, hashlib, hmac, json, os, subprocess, sys, time
from pathlib import Path
from urllib.request import Request, urlopen

MAX_CARD_EVIDENCE = 8
MAX_CARD_LINKS = 6

def rows(path):
    if not path: return []
    with open(path,encoding="utf-8") as f: return [json.loads(x) for x in f if x.strip()]
def key(row): return f"{row.get('brand_id',row.get('brand'))}:{row.get('domain')}"
def fingerprint(row):
    value={k:row.get(k) for k in ("risk_score","brand_similarity","abuse_likelihood","risk_factors")}
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()
def as_url(value):
    if not isinstance(value, str): return None
    candidate=value.strip()
    if candidate.startswith(("https://", "http://")): return candidate
    return None
def display_url(url):
    return url.removeprefix("https://").removeprefix("http://").rstrip("/")
def markdown_link(label, url):
    return f"[{label}]({url})"
def candidate_url(row):
    return as_url(row.get("url")) or f"https://{row.get('domain')}"
def profile_index(directory):
    if not directory: return {}
    result={}
    for path in sorted(Path(directory).glob("*.json")):
        try:
            profile=json.loads(path.read_text(encoding="utf-8"))
            if profile.get("brand_id"): result[profile["brand_id"]]=profile
        except (OSError, json.JSONDecodeError):
            continue
    return result
def official_links(row, profiles, language):
    profile=profiles.get(row.get("brand_id"), {})
    domains=profile.get("official_domains", row.get("official_domains", []))
    if isinstance(domains, str): domains=[domains]
    prefix="Official site" if language == "en" else "官网"
    return [(f"{prefix}: {domain}", f"https://{domain}") for domain in domains if isinstance(domain, str) and domain]
def source_summary(source):
    data=source.get("data") if isinstance(source.get("data"), dict) else {}
    raw=data.get("raw") if isinstance(data.get("raw"), dict) else {}
    parts=[str(source.get("kind", "unknown")), str(source.get("status", "unknown"))]
    for name in ("ip", "ips", "title", "registrar", "issuer", "status_code"):
        value=data.get(name)
        if value not in (None, "", []):
            if isinstance(value, list): value=", ".join(map(str, value[:3]))
            parts.append(f"{name}={str(value)[:100]}")
    if source.get("kind") == "dns":
        records=data.get("records", {})
        addresses=records.get("a", []) if isinstance(records, dict) else []
        if addresses: parts.append("A="+", ".join(map(str, addresses[:3])))
    if source.get("kind") == "rdap" and raw:
        registered=next((event.get("eventDate") for event in raw.get("events", []) if event.get("eventAction") == "registration"), None)
        if registered: parts.append("registered="+str(registered))
        nameservers=[item.get("ldhName") for item in raw.get("nameservers", []) if item.get("ldhName")]
        if nameservers: parts.append("NS="+", ".join(nameservers[:2]))
    if source.get("kind") == "certificate_transparency" and raw:
        for name in ("common_name", "not_before", "issuer_name"):
            if raw.get(name): parts.append(f"{name}={str(raw[name])[:100]}")
    return " ｜ ".join(parts)
def evidence_links(row):
    links=[]
    for source in row.get("sources", []):
        data=source.get("data") if isinstance(source.get("data"), dict) else {}
        for field in ("url", "final_url", "page_url", "location", "source_url"):
            url=as_url(data.get(field))
            if url and url not in {item[1] for item in links}:
                links.append((f"{source.get('kind', '证据')}：{display_url(url)}", url))
    return links
def context_index(path):
    if not path: return {}
    try:
        data=json.loads(Path(path).read_text(encoding="utf-8"))
        return data.get("findings", data) if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}
def context_links(context):
    links=[]
    for item in context.get("links", []) if isinstance(context, dict) else []:
        if isinstance(item, dict) and isinstance(item.get("label"), str):
            url=as_url(item.get("url"))
            if url: links.append((item["label"], url))
    return links
def lines(value):
    if isinstance(value, list): return [str(item) for item in value if item]
    return [str(value)] if value else []
def localized_context(context, language):
    if language == "zh" or not isinstance(context, dict): return context or {}
    translated=context.get("translations", {}).get(language, {})
    return {**context, **translated} if isinstance(translated, dict) else context
def card(row,case=None,profiles=None,context=None,language="zh"):
    profiles=profiles or {}
    context=localized_context(context, language)
    labels={
        "zh":{"conclusion":"初步结论","site":"疑似站","brand":"受保护品牌","score":"内部风险评分","why":"为什么需要关注","evidence":"已核验证据","promotion":"外部传播线索","coverage":"本次排查范围","next":"建议下一步","open":"打开疑似页面","title":"品牌仿冒域名告警｜待人工复核","boundary":"系统结论仅用于人工复核，不等同于恶意定性；不会自动提交投诉、下架或封禁。"},
        "en":{"conclusion":"Initial assessment","site":"Suspected site","brand":"Protected brand","score":"Internal risk score","why":"Why this needs attention","evidence":"Verified evidence","promotion":"External promotion leads","coverage":"Scope of this scan","next":"Recommended next step","open":"Open suspected site","title":"Brand impersonation alert | Human review required","boundary":"This is an internal review finding, not a final maliciousness determination. The system does not automatically report, take down, or block a site."}
    }[language]
    factors="、".join(row.get("risk_factors",[])[:10]) or "待补充证据"
    domain_url=candidate_url(row)
    conclusion=context.get("conclusion") or ("A high-priority suspected impersonation or unauthorized brand-use site requires internal review." if language == "en" else "发现高优先级疑似仿冒/未授权品牌使用站，需内部复核。")
    why=context.get("why") or (f"The domain is strongly related to the protected brand. Risk signals: {factors}." if language == "en" else f"域名与受保护品牌高度相关，风险依据：{factors}。")
    score_note="for triage only; not a maliciousness determination" if language == "en" else "用于排查排序，不代表恶意定性"
    overview=(f"**{labels['conclusion']}**：{conclusion}\n\n"
              f"**{labels['site']}**：{markdown_link(display_url(domain_url), domain_url)}\n"
              f"**{labels['brand']}**：{row.get('brand', 'Unspecified' if language == 'en' else '未标注')}\n"
              f"**{labels['score']}**：{row.get('risk_score', 0)}（{score_note}）")
    sources=row.get("sources", [])
    evidence="\n".join(f"- {source_summary(source)}" for source in sources[:MAX_CARD_EVIDENCE]) or "- 暂无可展示证据"
    if len(sources)>MAX_CARD_EVIDENCE: evidence+=f"\n- 另有 {len(sources)-MAX_CARD_EVIDENCE} 项证据未在卡片展开"
    promotion=lines(context.get("promotion"))
    coverage=context.get("coverage") or (f"Evidence coverage: {row.get('evidence_completeness', 0)}%; observed: {row.get('collected_at', 'not recorded')}." if language == "en" else f"本次证据覆盖：{row.get('evidence_completeness', 0)}%；发现时间：{row.get('collected_at', '未记录')}。")
    next_step=context.get("next_step") or ("Confirm whether this activity is authorized. If not, have legal or security decide on reporting, takedown, or blocking after review." if language == "en" else "请先确认该业务是否已获授权；未获授权时，再由法务或安全团队决定投诉、下架或封禁动作。")
    links=[(labels["open"], domain_url), *official_links(row, profiles, language), *context_links(context), *evidence_links(row)]
    deduped=[]
    for label, url in links:
        if url not in {item[1] for item in deduped}: deduped.append((label, url))
    actions=[{"tag":"button","text":{"tag":"plain_text","content":label[:80]},"type":"danger" if i == 0 else "default","url":url}
             for i,(label,url) in enumerate(deduped[:MAX_CARD_LINKS])]
    elements=[
        {"tag":"markdown","content":overview},
        {"tag":"hr"},
        {"tag":"markdown","content":f"**{labels['why']}**\n"+why},
        {"tag":"markdown","content":f"**{labels['evidence']}**\n"+evidence},
        *([{ "tag":"markdown", "content":f"**{labels['promotion']}**\n"+"\n".join(f"- {item}" for item in promotion)}] if promotion else []),
        {"tag":"markdown","content":f"**{labels['coverage']}**\n"+coverage},
        {"tag":"markdown","content":f"**{labels['next']}**\n"+next_step+"\n\n"+labels["boundary"]},
    ]
    if actions: elements.append({"tag":"action","actions":actions})
    return {"msg_type":"interactive","card":{"header":{"title":{"tag":"plain_text","content":labels["title"]},"template":"red"},"elements":elements}}
def sign(payload,secret):
    ts=str(int(time.time())); token=base64.b64encode(hmac.new((ts+"\n"+secret).encode(),digestmod=hashlib.sha256).digest()).decode()
    payload.update({"timestamp":ts,"sign":token})
def post(url,payload):
    req=Request(url,data=json.dumps(payload).encode(),headers={"Content-Type":"application/json","User-Agent":"BrandImpersonationMonitor/1.0"})
    with urlopen(req,timeout=15) as r: result=json.loads(r.read().decode())
    if result.get("code",0)!=0: raise RuntimeError("Lark rejected alert: "+str(result.get("msg",result)))
def credential(env_name, keychain_service):
    value=os.getenv(env_name)
    if value: return value
    try:
        return subprocess.run(["security","find-generic-password","-a","brand-impersonation-monitor","-s",keychain_service,"-w"],capture_output=True,text=True,check=True).stdout.strip()
    except (OSError,subprocess.CalledProcessError):
        return None
def main():
    p=argparse.ArgumentParser(); p.add_argument("--input",required=True); p.add_argument("--changes"); p.add_argument("--cases"); p.add_argument("--profiles",help="Directory of approved brand profiles, used to add official-site links"); p.add_argument("--context",help="Verified human-readable finding context JSON, keyed by brand_id:domain"); p.add_argument("--language",choices=("zh","en"),default="zh"); p.add_argument("--open-statuses",default="new,triaged"); p.add_argument("--state",required=True); p.add_argument("--preview",required=True); p.add_argument("--min-score",type=int,default=70); p.add_argument("--limit",type=int,default=20); p.add_argument("--send",action="store_true"); p.add_argument("--webhook-env",default="LARK_WEBHOOK_URL"); p.add_argument("--secret-env",default="LARK_WEBHOOK_SECRET"); a=p.parse_args()
    changed={key(x) for x in rows(a.changes)} if a.changes else None; state=json.loads(Path(a.state).read_text()) if Path(a.state).exists() else {}; chosen=[]
    cases=json.loads(Path(a.cases).read_text()).get("cases",{}) if a.cases else None; open_statuses={x.strip() for x in a.open_statuses.split(",") if x.strip()}
    for row in sorted(rows(a.input),key=lambda x:-x.get("risk_score",0)):
        k=key(row); fp=fingerprint(row)
        case=cases.get(k) if cases is not None else None
        if row.get("risk_score",0)<a.min_score or (changed is not None and k not in changed) or state.get(k)==fp: continue
        if cases is not None and (case is None or case.get("status") not in open_statuses): continue
        chosen.append((k,fp,row,case))
    chosen=chosen[:a.limit]
    profiles=profile_index(a.profiles)
    contexts=context_index(a.context)
    Path(a.preview).write_text("\n".join(json.dumps(card(x[2],x[3],profiles,contexts.get(x[0]),a.language),ensure_ascii=False) for x in chosen)+("\n" if chosen else ""),encoding="utf-8")
    if not a.send:
        print(f"previewed {len(chosen)} alert cards; not sent")
        return
    url=credential(a.webhook_env,"brand-impersonation-monitor:lark-webhook-url")
    if not url: sys.exit(f"error: {a.webhook_env} or macOS Keychain webhook entry is required when --send is used")
    secret=credential(a.secret_env,"brand-impersonation-monitor:lark-webhook-secret")
    for k,fp,row,case in chosen:
        payload=card(row,case,profiles,contexts.get(k),a.language)
        if secret: sign(payload,secret)
        post(url,payload); state[k]=fp
    Path(a.state).write_text(json.dumps(state,indent=2,sort_keys=True),encoding="utf-8")
    print(f"sent {len(chosen)} Lark alert cards")
if __name__=="__main__": main()
