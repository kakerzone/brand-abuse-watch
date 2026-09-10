#!/usr/bin/env python3
"""Check local monitor artifacts and report operational readiness without network access."""
import argparse,json,sqlite3,sys
from pathlib import Path
def main():
 p=argparse.ArgumentParser(); p.add_argument('--workdir',required=True); a=p.parse_args(); w=Path(a.workdir); errors=[]; warnings=[]
 for name in ['run-manifest.json','rescored.jsonl','cases.json','monitor.sqlite']:
  if not (w/name).exists(): errors.append('missing '+name)
 if (w/'rescored.jsonl').exists() and not (w/'rescored.jsonl').read_text().strip(): warnings.append('no findings in latest run')
 if (w/'monitor.sqlite').exists():
  try: sqlite3.connect(w/'monitor.sqlite').execute('select 1 from findings limit 1')
  except sqlite3.Error as e: errors.append('sqlite unavailable: '+str(e))
 if (w/'cases.json').exists():
  cases=json.loads((w/'cases.json').read_text()).get('cases',{}); open_cases=sum(x.get('status') in {'new','triaged','confirmed_impersonation','takedown_pending'} for x in cases.values()); print('open_cases='+str(open_cases))
 for x in warnings: print('WARNING: '+x)
 for x in errors: print('ERROR: '+x,file=sys.stderr)
 if errors: sys.exit(1)
 print('OK: local artifacts healthy')
if __name__=='__main__': main()
