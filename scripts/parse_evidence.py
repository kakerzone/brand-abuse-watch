#!/usr/bin/env python3
"""Normalize provider exports into evidence JSONL; never performs network collection."""
import argparse, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

FQDN=re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",re.I)
def now(): return datetime.now(timezone.utc).isoformat()
def canon(value):
    if not value: return None
    value=str(value).strip().lower().rstrip(".")
    if "://" in value: value=urlparse(value).hostname or ""
    try: value=value.encode("idna").decode("ascii")
    except UnicodeError: return None
    return value if FQDN.fullmatch(value) else None
def load(path):
    raw=Path(path).read_bytes(); digest=hashlib.sha256(raw).hexdigest()
    text=raw.decode("utf-8","replace").strip()
    try: data=json.loads(text)
    except json.JSONDecodeError: data=[json.loads(x) for x in text.splitlines() if x.strip()]
    if isinstance(data,dict): data=data.get("data",data.get("results",data.get("records",[data])))
    return (data if isinstance(data,list) else [data]),digest
def domains(source,r):
    if source=="ct": return [canon(x) for x in str(r.get("name_value",r.get("common_name",""))).splitlines()]
    if source=="rdap": return [canon(r.get("ldhName",r.get("domain")))]
    if source=="http": return [canon(r.get("domain") or r.get("host") or r.get("url"))]
    if source=="dns": return [canon(r.get("domain") or r.get("name") or r.get("hostname"))]
    if source=="passive_dns": return [canon(r.get("domain") or r.get("rrname") or r.get("query"))]
    if source=="threat_intelligence":
        a=r.get("attributes",{}) if isinstance(r.get("attributes"),dict) else {}
        return [canon(r.get("domain") or r.get("id") or a.get("domain"))]
    return [canon(r.get("domain"))]
def normalize(source, path, collected_at):
    rows,digest=load(path); out=[]; stamp=collected_at or now()
    for r in rows:
        if not isinstance(r,dict): continue
        for d in filter(None,domains(source,r)):
            out.append({"domain":d,"collected_at":stamp,"sources":[{"kind":source,"collected_at":stamp,"status":"ok","data":{"raw":r,"raw_sha256":digest}}]})
    return out
def read_jsonl(path):
    with open(path,encoding="utf-8") as f: return [json.loads(x) for x in f if x.strip()]
def write(path,rows):
    with open(path,"w",encoding="utf-8") as f:
        for r in rows: f.write(json.dumps(r,ensure_ascii=False,sort_keys=True)+"\n")
def merge(findings,evidence):
    index={}
    for finding in findings:
        d=canon(finding.get("domain"))
        if d: index.setdefault(d,[]).append(finding)
    unmatched=[]
    for e in evidence:
        d=canon(e.get("domain"))
        if d in index:
            for finding in index[d]: finding.setdefault("sources",[]).extend(e.get("sources",[]))
        else: unmatched.append(e)
    return findings,unmatched
def union(left,right):
    index={}
    for row in left+right:
        key=(str(row.get("brand_id",row.get("brand","unknown"))),canon(row.get("domain")))
        if not key[1]: continue
        if key not in index:
            index[key]=row
            continue
        base=index[key]
        base["sources"]=base.get("sources",[])+row.get("sources",[])
        base["candidate_reasons"]=sorted(set(base.get("candidate_reasons",[])+row.get("candidate_reasons",[])))
        base["risk_factors"]=sorted(set(base.get("risk_factors",[])+row.get("risk_factors",[])))
        for field in ("risk_score","brand_similarity","abuse_likelihood","evidence_completeness"):
            base[field]=max(base.get(field,0),row.get(field,0))
    return list(index.values())
def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    n=sub.add_parser("normalize"); n.add_argument("--source",required=True,choices=("dns","ct","rdap","http","passive_dns","threat_intelligence","custom")); n.add_argument("--input",required=True); n.add_argument("--output",required=True); n.add_argument("--collected-at")
    m=sub.add_parser("merge"); m.add_argument("--findings",required=True); m.add_argument("--evidence",required=True); m.add_argument("--output",required=True); m.add_argument("--unmatched")
    u=sub.add_parser("union"); u.add_argument("--left",required=True); u.add_argument("--right",required=True); u.add_argument("--output",required=True)
    a=p.parse_args()
    if a.cmd=="normalize": write(a.output,normalize(a.source,a.input,a.collected_at))
    elif a.cmd=="merge":
        rows,unmatched=merge(read_jsonl(a.findings),read_jsonl(a.evidence)); write(a.output,rows)
        if a.unmatched: write(a.unmatched,unmatched)
    else:
        write(a.output,union(read_jsonl(a.left),read_jsonl(a.right)))
if __name__=="__main__": main()
