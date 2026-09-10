#!/usr/bin/env python3
"""Explicit-network, non-interactive HTML/header capture for high-risk candidates."""
import argparse, hashlib, json, re, sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

NOW=lambda: datetime.now(timezone.utc).isoformat()
def safe_name(domain): return re.sub(r'[^a-zA-Z0-9._-]','_',domain)
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*a,**k): return None
def capture(domain,out):
 url='https://'+domain+'/'
 req=Request(url,headers={'User-Agent':'BrandImpersonationMonitor/1.0','Accept':'text/html,application/xhtml+xml'})
 try:
  opener=build_opener(ProxyHandler({}),NoRedirect)
  with opener.open(req,timeout=12) as response:
   body=response.read(262144); headers=dict(response.headers.items()); status=response.status
  status_text='ok'
 except HTTPError as e:
  body=e.read(262144); headers=dict(e.headers.items()); status=e.code; status_text='http_error'
 except (URLError,TimeoutError,OSError) as e:
  return {'domain':domain,'collected_at':NOW(),'status':'unavailable','error':str(e)}
 base=out/safe_name(domain); base.mkdir(parents=True,exist_ok=True)
 (base/'response.html').write_bytes(body); meta={'domain':domain,'url':url,'collected_at':NOW(),'status':status,'headers':headers,'body_sha256':hashlib.sha256(body).hexdigest(),'body_bytes':len(body),'capture_mode':'https_no_redirect_no_js_no_auth'}
 (base/'metadata.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding='utf-8')
 return {'domain':domain,'collected_at':NOW(),'status':status_text,'capture_dir':str(base),'metadata':meta}
def main():
 p=argparse.ArgumentParser(); p.add_argument('--input',required=True); p.add_argument('--output-dir',required=True); p.add_argument('--index',required=True); p.add_argument('--network',action='store_true'); p.add_argument('--min-score',type=int,default=70); p.add_argument('--limit',type=int,default=20); a=p.parse_args()
 if not a.network: sys.exit('error: web capture requires --network')
 with open(a.input,encoding='utf-8') as f: rows=[json.loads(x) for x in f if x.strip()]
 selected=sorted((x for x in rows if x.get('risk_score',0)>=a.min_score),key=lambda x:-x['risk_score'])[:a.limit]; out=Path(a.output_dir); out.mkdir(parents=True,exist_ok=True)
 result=[capture(x['domain'],out) for x in selected]
 with open(a.index,'w',encoding='utf-8') as f:
  for x in result: f.write(json.dumps(x,ensure_ascii=False,sort_keys=True)+'\n')
if __name__=='__main__': main()
