#!/usr/bin/env python3
"""Recompute explainable brand similarity, abuse likelihood, and coverage from evidence."""
import argparse, json
from pathlib import Path

COLLECTORS={"dns","http","certificate_transparency","rdap","passive_dns","threat_intelligence","web_capture","visual_fingerprint"}
def load_jsonl(path):
    with open(path,encoding="utf-8") as f: return [json.loads(x) for x in f if x.strip()]
def profiles(path):
    out={}
    for f in Path(path).glob("*.json"):
        p=json.loads(f.read_text(encoding="utf-8")); out[str(p.get("brand_id",p.get("brand")))]=p
    return out
def hamming(a,b): return (int(a,16)^int(b,16)).bit_count()
def assess(row,profile):
    similarity=int(row.get("brand_similarity",0)); abuse=int(row.get("abuse_likelihood",0)); factors=list(row.get("risk_factors",[])); seen=set()
    official_ips={str(x) for x in profile.get("official_ips",[])}; official_visual=profile.get("official_visual_hashes",[])
    for s in row.get("sources",[]):
        kind=s.get("kind"); data=s.get("data",{}); raw=data.get("raw",{}) if isinstance(data.get("raw"),dict) else {}; seen.add(kind)
        if kind=="web_capture":
            if data.get("brand_mentions"): similarity+=15; factors.append("protected brand mentioned in captured page")
            if data.get("credential_form"): abuse+=25; factors.append("credential form in captured page")
            if data.get("payment_form"): abuse+=20; factors.append("payment-related form in captured page")
        if kind=="visual_fingerprint":
            for official in official_visual:
                if data.get("dhash") and official.get("dhash") and hamming(data["dhash"],official["dhash"])<=int(official.get("max_distance",12)):
                    similarity+=20; factors.append("visual fingerprint similar to official asset"); break
        if kind=="dns":
            addresses=data.get("addresses",[])+data.get("records",{}).get("a",[])+data.get("records",{}).get("aaaa",[])
            if official_ips.intersection(map(str,addresses)): abuse-=30; factors.append("resolves to configured official IP")
        if kind=="threat_intelligence" and (data.get("malicious") or raw.get("malicious")): abuse+=30; factors.append("threat-intelligence malicious signal")
    similarity=max(0,min(100,similarity)); abuse=max(0,min(100,abuse)); coverage=round(100*len(seen.intersection(COLLECTORS))/len(COLLECTORS))
    priority=round((similarity+abuse)/2)
    if row.get("domain") in {str(x).lower().rstrip(".") for x in profile.get("allowlist",[])}: priority=0; factors.append("allowlisted asset")
    row.update({"brand_similarity":similarity,"abuse_likelihood":abuse,"evidence_completeness":coverage,"risk_score":priority,"risk_factors":sorted(set(factors))})
    return row
def main():
    p=argparse.ArgumentParser(); p.add_argument("--input",required=True); p.add_argument("--profiles",required=True); p.add_argument("--output",required=True); a=p.parse_args(); ps=profiles(a.profiles); out=[]
    for row in load_jsonl(a.input):
        key=str(row.get("brand_id",row.get("brand"))); out.append(assess(row,ps[key]) if key in ps else row)
    with open(a.output,"w",encoding="utf-8") as f:
        for row in out: f.write(json.dumps(row,ensure_ascii=False,sort_keys=True)+"\n")
if __name__=="__main__": main()
