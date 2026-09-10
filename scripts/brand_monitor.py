#!/usr/bin/env python3
"""Offline candidate discovery plus explicit-network enrichment and stateful change tracking."""
import argparse, hashlib, json, re, socket, sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler

NOW = lambda: datetime.now(timezone.utc).isoformat()
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)

def read_json(path):
    with open(path, encoding="utf-8") as f: return json.load(f)
def jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]
def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows: f.write(json.dumps(r, sort_keys=True) + "\n")
def canon(d):
    try: return str(d).strip().rstrip(".").lower().encode("idna").decode("ascii")
    except UnicodeError: return ""
def valid(d): return bool(DOMAIN.fullmatch(canon(d)))
def score(reasons, allowlisted):
    if allowlisted: return 0, ["allowlisted asset"], 0, 0
    pts = {"brand":30, "high_keyword":25, "phishing_keyword":15, "typo":15, "homoglyph":20, "hyphen":8, "tld":5}
    brand_similarity=min(100, (70 if "brand" in reasons else 0)+(50 if "typo" in reasons else 0)+(10 if "hyphen" in reasons else 0))
    abuse_likelihood=min(100, (55 if "high_keyword" in reasons else 0)+(35 if "phishing_keyword" in reasons else 0))
    return min(100, sum(pts.get(x, 0) for x in reasons)), sorted(reasons), brand_similarity, abuse_likelihood

def typos(label):
    out=set()
    for i in range(len(label)):
        out.add(label[:i]+label[i+1:])
        if i < len(label)-1: out.add(label[:i]+label[i+1]+label[i]+label[i+2:])
    for a,b in {"o":"0","i":"1","l":"1","s":"5","a":"4","e":"3"}.items():
        out.update(label[:i]+b+label[i+1:] for i,c in enumerate(label) if c==a)
    # Common cross-script confusables are emitted as IDNA/Punycode candidates by canon().
    confusables={"a":"а","c":"с","e":"е","i":"і","j":"ј","o":"ο","p":"р","s":"ѕ","x":"х","y":"у"}
    for a,b in confusables.items():
        out.update(label[:i]+b+label[i+1:] for i,c in enumerate(label) if c==a)
    return {x for x in out if x and x != label}

def discover(profile):
    brand=str(profile["brand"]).lower().replace(" ", "")
    aliases={brand, *(str(x).lower().replace(" ", "") for x in profile.get("aliases", []))}
    tlds={str(x).lower().lstrip(".") for x in profile.get("tlds", ["com"])}
    high={str(x).lower() for x in profile.get("risk_keywords", {}).get("high", [])}
    phish={str(x).lower() for x in profile.get("risk_keywords", {}).get("phishing", [])}
    allow={canon(x) for x in profile.get("allowlist", [])}
    candidates={}
    def add(domain, reasons):
        domain=canon(domain)
        if valid(domain): candidates.setdefault(domain, set()).update(reasons)
    for alias in aliases:
        for tld in tlds:
            for word in high|phish:
                reason="high_keyword" if word in high else "phishing_keyword"
                for name in (f"{alias}-{word}",f"{word}-{alias}",f"{alias}{word}",f"{word}{alias}"):
                    add(f"{name}.{tld}", {"brand",reason,"tld"})
            for typo in typos(alias): add(f"{typo}.com", {"typo"} | ({"homoglyph"} if any(ord(c)>127 for c in typo) else set()))
            for i in range(1,len(alias)): add(f"{alias[:i]}-{alias[i:]}.{tld}", {"brand","hyphen","tld"})
    rows=[]
    for domain,reasons in sorted(candidates.items()):
        s,f,similarity,abuse=score(reasons, domain in allow)
        rows.append({"domain":domain,"brand_id":profile.get("brand_id",profile["brand"]),"brand":profile["brand"],"candidate_reasons":sorted(reasons),"risk_score":s,"brand_similarity":similarity,"abuse_likelihood":abuse,"evidence_completeness":0,"risk_factors":f,"collected_at":NOW(),"sources":[{"kind":"generator","collected_at":NOW(),"status":"ok","data":{"offline":True}}]})
    # Preserve high-value Unicode-homoglyph coverage before applying a profile cap.
    rows.sort(key=lambda r:("homoglyph" not in r["candidate_reasons"],-r["risk_score"],r["domain"]))
    return rows[:int(profile.get("max_candidates",500))]

def dns(domain):
    try:
        items=socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return {"addresses":sorted({x[4][0] for x in items})}
    except socket.gaierror as e: return {"addresses":[],"error":str(e)}
def http(domain):
    # No redirects are followed: this only captures the first HTTPS response safely.
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self,*a,**k): return None
    req=Request("https://"+domain+"/", headers={"User-Agent":"BrandMonitor/1.0","Accept":"text/html"})
    try:
        with build_opener(NoRedirect).open(req, timeout=8) as r:
            data=r.read(65536).decode("utf-8","replace")
            title=re.search(r"<title[^>]*>(.*?)</title>",data,re.I|re.S)
            return {"status":r.status,"location":r.headers.get("Location"),"title":re.sub(r"\s+"," ",title.group(1)).strip()[:300] if title else None}
    except HTTPError as e: return {"status":e.code,"location":e.headers.get("Location")}
    except (URLError,TimeoutError,OSError) as e: return {"error":str(e)}
def enrich(rows, network, limit):
    if not network: raise ValueError("Network enrichment requires --network")
    for r in sorted(rows,key=lambda x:x.get("risk_score",0),reverse=True)[:limit]:
        stamp=NOW(); d=dns(r["domain"]); h=http(r["domain"])
        r["sources"] += [{"kind":"dns","collected_at":stamp,"status":"ok" if d.get("addresses") else "unavailable","data":d},{"kind":"http","collected_at":stamp,"status":"ok" if "status" in h else "unavailable","data":h}]
        # Built-in collectors cover only DNS and bounded HTTP out of eight documented evidence categories.
        r["evidence_completeness"]=25
        if d.get("addresses"): r["risk_score"]=min(100,r["risk_score"]+10); r["abuse_likelihood"]=min(100,r.get("abuse_likelihood",0)+10); r["risk_factors"].append("resolves to network address")
    return rows
def fingerprint(row):
    sources=[{"kind":x["kind"],"data":x.get("data",{})} for x in row.get("sources",[]) if x["kind"]!="generator"]
    return hashlib.sha256(json.dumps(sources,sort_keys=True).encode()).hexdigest()
def track(rows, state_path):
    state=read_json(state_path) if Path(state_path).exists() else {}
    changes=[]
    for r in rows:
        key=f"{r.get('brand_id',r.get('brand','unknown'))}:{r['domain']}"; f=fingerprint(r); old=state.get(key)
        if old is None: changes.append({"brand_id":r.get("brand_id"),"domain":r["domain"],"event":"new_candidate","at":NOW(),"risk_score":r["risk_score"]})
        elif old["fingerprint"] != f: changes.append({"brand_id":r.get("brand_id"),"domain":r["domain"],"event":"evidence_changed","at":NOW(),"risk_score":r["risk_score"]})
        state[key]={"fingerprint":f,"last_seen":NOW(),"risk_score":r["risk_score"]}
    with open(state_path,"w",encoding="utf-8") as f: json.dump(state,f,indent=2,sort_keys=True)
    return changes
def report(rows, changes):
    buckets={"high":[],"medium":[],"low":[]}
    for r in rows: buckets["high" if r["risk_score"]>=70 else "medium" if r["risk_score"]>=40 else "low"].append(r)
    lines=["# Brand impersonation monitoring report","",f"Generated: {NOW()}",f"Material events: {len(changes)}",""]
    for k in ("high","medium","low"):
        lines += [f"## {k.title()} risk ({len(buckets[k])})",""]
        lines += [f"- `{r['domain']}` — {r['risk_score']} — {', '.join(r['risk_factors'])}" for r in buckets[k]] or ["- None"]
        lines.append("")
    lines += ["## Coverage", "Built-in collection: offline candidate generation; explicit-network DNS and bounded HTTPS headers/title. RDAP, CT, MX/NS, passive DNS, screenshots, and threat intelligence were not queried unless represented in source evidence."]
    return "\n".join(lines)
def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("discover"); a.add_argument("--profile",required=True); a.add_argument("--output",required=True)
    a=sub.add_parser("enrich"); a.add_argument("--input",required=True); a.add_argument("--output",required=True); a.add_argument("--network",action="store_true"); a.add_argument("--limit",type=int,default=50)
    a=sub.add_parser("track"); a.add_argument("--input",required=True); a.add_argument("--state",required=True); a.add_argument("--changes",required=True)
    a=sub.add_parser("report"); a.add_argument("--input",required=True); a.add_argument("--changes",required=True); a.add_argument("--output",required=True)
    x=p.parse_args()
    if x.cmd=="discover": write_jsonl(x.output,discover(read_json(x.profile)))
    elif x.cmd=="enrich": write_jsonl(x.output,enrich(jsonl(x.input),x.network,x.limit))
    elif x.cmd=="track": write_jsonl(x.changes,track(jsonl(x.input),x.state))
    else: Path(x.output).write_text(report(jsonl(x.input),jsonl(x.changes)),encoding="utf-8")
if __name__=="__main__":
    try: main()
    except (ValueError,KeyError,json.JSONDecodeError) as e: sys.exit("error: "+str(e))
