#!/usr/bin/env python3
"""Local, source-transparent retrieval for JSONL brand-monitor findings."""
import argparse, json
from datetime import datetime

def records(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip(): yield json.loads(line)
def text(r):
    return " ".join([r.get("domain", ""), r.get("brand", ""), *r.get("candidate_reasons", []), *r.get("risk_factors", [])]).lower()
def tier(score): return "high" if score >= 70 else "medium" if score >= 40 else "low"
def main():
    p=argparse.ArgumentParser(description="Filter local brand-monitor JSONL findings")
    p.add_argument("--input",required=True); p.add_argument("--contains")
    p.add_argument("--brand"); p.add_argument("--brand-id"); p.add_argument("--reason"); p.add_argument("--source")
    p.add_argument("--min-score",type=int,default=0); p.add_argument("--tier",choices=("high","medium","low"))
    p.add_argument("--after",help="ISO timestamp inclusive"); p.add_argument("--limit",type=int,default=100)
    a=p.parse_args(); out=[]
    for r in records(a.input):
        if a.contains and a.contains.lower() not in text(r): continue
        if a.brand and a.brand.lower()!=str(r.get("brand","")).lower(): continue
        if a.brand_id and a.brand_id!=str(r.get("brand_id","")): continue
        if a.reason and a.reason not in r.get("candidate_reasons",[]): continue
        if a.source and a.source not in {x.get("kind") for x in r.get("sources",[])}: continue
        if r.get("risk_score",0)<a.min_score: continue
        if a.tier and tier(r.get("risk_score",0))!=a.tier: continue
        if a.after and r.get("collected_at","")<a.after: continue
        out.append(r)
    out.sort(key=lambda x:(-x.get("risk_score",0),x.get("domain","")))
    for r in out[:a.limit]:
        print(json.dumps({"domain":r.get("domain"),"brand_id":r.get("brand_id"),"brand":r.get("brand"),"risk_score":r.get("risk_score"),"brand_similarity":r.get("brand_similarity"),"abuse_likelihood":r.get("abuse_likelihood"),"evidence_completeness":r.get("evidence_completeness"),"tier":tier(r.get("risk_score",0)),"reasons":r.get("candidate_reasons",[]),"sources":[x.get("kind") for x in r.get("sources",[])]},ensure_ascii=False))
if __name__=="__main__": main()
