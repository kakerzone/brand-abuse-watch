#!/usr/bin/env python3
"""Run dnstwist for approved profile domains and emit normalized brand findings."""
import argparse, json, shutil, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

NOW=lambda: datetime.now(timezone.utc).isoformat()
DNSTWIST_BIN=Path(__file__).resolve().parent.parent/'.venv/bin/dnstwist'
def binary(): return str(DNSTWIST_BIN) if DNSTWIST_BIN.exists() else shutil.which('dnstwist')
def load_profiles(path):
    p=Path(path); files=[p] if p.is_file() else sorted(p.glob('*.json'))
    return [json.loads(x.read_text(encoding='utf-8')) for x in files]
def scan(profile,domain):
    try:
        result=subprocess.run([binary(),'-r','-f','json',domain],capture_output=True,text=True,timeout=180,check=True)
        records=json.loads(result.stdout)
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired,json.JSONDecodeError) as e:
        return [{'brand_id':profile.get('brand_id',profile['brand']),'brand':profile['brand'],'domain':domain,'candidate_reasons':['dnstwist_scan_error'],'risk_score':0,'brand_similarity':0,'abuse_likelihood':0,'evidence_completeness':0,'risk_factors':[str(e)],'collected_at':NOW(),'sources':[{'kind':'dnstwist','collected_at':NOW(),'status':'unavailable','data':{}}]}]
    out=[]
    for r in records:
        candidate=str(r.get('domain','')).lower().rstrip('.')
        if not candidate or candidate==domain: continue
        addresses=r.get('dns_a',[])+r.get('dns_aaaa',[])
        if not addresses: continue
        fuzzer=r.get('fuzzer','unknown'); homo=fuzzer=='homoglyph'; score=45 if homo else 30
        out.append({'brand_id':profile.get('brand_id',profile['brand']),'brand':profile['brand'],'domain':candidate,'candidate_reasons':['dnstwist',fuzzer],'risk_score':score,'brand_similarity':80 if homo else 55,'abuse_likelihood':10,'evidence_completeness':12,'risk_factors':['dnstwist '+fuzzer,'resolves to network address'],'collected_at':NOW(),'sources':[{'kind':'dnstwist','collected_at':NOW(),'status':'ok','data':{'source_domain':domain,'fuzzer':fuzzer,'addresses':addresses,'raw':r}}]})
    return out
def main():
    p=argparse.ArgumentParser(); p.add_argument('--profiles',required=True); p.add_argument('--output',required=True); p.add_argument('--network',action='store_true'); p.add_argument('--max-domains',type=int,default=20); a=p.parse_args()
    if not a.network: sys.exit('error: dnstwist collection requires --network')
    if not binary(): sys.exit('error: dnstwist is not installed; install it before enabling this collector')
    out=[]
    for profile in load_profiles(a.profiles):
        for domain in profile.get('official_domains',[])[:a.max_domains]: out.extend(scan(profile,domain))
    with open(a.output,'w',encoding='utf-8') as f:
        for row in out: f.write(json.dumps(row,ensure_ascii=False,sort_keys=True)+'\n')
if __name__=='__main__': main()
