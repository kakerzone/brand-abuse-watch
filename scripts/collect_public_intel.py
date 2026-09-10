#!/usr/bin/env python3
"""Explicit-network collectors for public CT, RDAP, and DNS evidence."""
import argparse, hashlib, json, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen
from importlib.util import spec_from_file_location, module_from_spec

spec=spec_from_file_location("parser",Path(__file__).with_name("parse_evidence.py")); parser=module_from_spec(spec); spec.loader.exec_module(parser)
NOW=lambda: datetime.now(timezone.utc).isoformat()
def write(path,rows):
    with open(path,"w",encoding="utf-8") as f:
        for r in rows: f.write(json.dumps(r,ensure_ascii=False,sort_keys=True)+"\n")
def request(url):
    req=Request(url,headers={"User-Agent":"BrandImpersonationMonitor/1.0","Accept":"application/json"})
    with urlopen(req,timeout=20) as r: return json.loads(r.read().decode("utf-8"))
def evidence(domain,kind,data,status="ok"):
    return {"domain":domain,"collected_at":NOW(),"sources":[{"kind":kind,"collected_at":NOW(),"status":status,"data":data}]}
def ct(query,limit):
    raw=request("https://crt.sh/?q="+quote(query)+"&output=json"); out=[]; seen=set(); stamp=NOW()
    for r in raw:
        for value in str(r.get("name_value","")).splitlines():
            d=parser.canon(value)
            if d and d not in seen:
                seen.add(d); out.append(evidence(d,"certificate_transparency",{"provider":"crt.sh","query":query,"raw":r,"raw_sha256":hashlib.sha256(json.dumps(r,sort_keys=True).encode()).hexdigest()}))
                if len(out)>=limit: return out
    return out
def rdap(domains,limit,delay):
    out=[]
    for d in domains[:limit]:
        try: raw=request("https://rdap.org/domain/"+quote(d)); out.append(evidence(d,"rdap",{"provider":"rdap.org","raw":raw}))
        except Exception as e: out.append(evidence(d,"rdap",{"provider":"rdap.org","error":str(e)},"unavailable"))
        time.sleep(delay)
    return out
def dig(domain,record):
    try:
        x=subprocess.run(["dig","+time=3","+tries=1","+short",record,domain],capture_output=True,text=True,timeout=8)
        return [z.strip() for z in x.stdout.splitlines() if z.strip()]
    except (OSError,subprocess.TimeoutExpired) as e: return {"error":str(e)}
def dns(domains,limit,delay):
    out=[]
    for d in domains[:limit]:
        data={k.lower():dig(d,k) for k in ("A","AAAA","CNAME","MX","NS")}
        out.append(evidence(d,"dns",{"provider":"system-dig","records":data}))
        time.sleep(delay)
    return out
def domains_from(path): return [parser.canon(x.get("domain")) for x in parser.read_jsonl(path) if parser.canon(x.get("domain"))]
def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("ct"); a.add_argument("--query",required=True); a.add_argument("--output",required=True); a.add_argument("--limit",type=int,default=200); a.add_argument("--network",action="store_true")
    for name in ("rdap","dns"):
        a=sub.add_parser(name); a.add_argument("--input",required=True); a.add_argument("--output",required=True); a.add_argument("--limit",type=int,default=50); a.add_argument("--delay",type=float,default=0.5); a.add_argument("--network",action="store_true")
    x=p.parse_args()
    if not x.network: sys.exit("error: public collection requires --network")
    rows=ct(x.query,x.limit) if x.cmd=="ct" else rdap(domains_from(x.input),x.limit,x.delay) if x.cmd=="rdap" else dns(domains_from(x.input),x.limit,x.delay)
    write(x.output,rows)
if __name__=="__main__": main()
