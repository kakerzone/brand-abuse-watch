#!/usr/bin/env python3
"""Run the local, non-network monitoring workflow for a profile directory."""
import argparse, json, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

HERE=Path(__file__).resolve().parent
def run(*args): subprocess.run([sys.executable,str(HERE/args[0]),*map(str,args[1:])],check=True)
def main():
 p=argparse.ArgumentParser(); p.add_argument('--profiles',required=True); p.add_argument('--workdir',required=True); p.add_argument('--evidence',action='append',default=[]); p.add_argument('--case-min-score',type=int,default=70); p.add_argument('--no-lark',action='store_true',help='Do not deliver Lark alerts for this run'); p.add_argument('--lark-preview-only',action='store_true',help='Generate cards but do not deliver them'); a=p.parse_args(); w=Path(a.workdir); w.mkdir(parents=True,exist_ok=True)
 run('validate_profiles.py','--profiles',a.profiles)
 findings=w/'findings.jsonl'; run('discover_profiles.py','--profiles',a.profiles,'--output',findings)
 current=findings
 for i,evidence in enumerate(a.evidence):
  merged=w/f'merged-{i}.jsonl'; run('parse_evidence.py','merge','--findings',current,'--evidence',evidence,'--output',merged); current=merged
 rescored=w/'rescored.jsonl'; run('rescore_findings.py','--input',current,'--profiles',a.profiles,'--output',rescored)
 changes=w/'changes.jsonl'; run('brand_monitor.py','track','--input',rescored,'--state',w/'monitor-state.json','--changes',changes)
 cases=w/'cases.json'; worklist=w/'open-cases.jsonl'; run('manage_cases.py','sync','--input',rescored,'--state',cases,'--worklist',worklist,'--min-score',a.case_min_score)
 db=w/'monitor.sqlite'; run('sqlite_index.py','import','--db',db,'--input',rescored)
 associations=w/'associations.jsonl'; run('correlate_findings.py','--input',rescored,'--output',associations)
 if not a.no_lark:
  args=['notify_lark.py','--input',rescored,'--changes',changes,'--cases',cases,'--profiles',a.profiles,'--state',w/'lark-alert-state.json','--preview',w/'lark-preview.jsonl']
  if not a.lark_preview_only: args.append('--send')
  run(*args)
 manifest={'ran_at':datetime.now(timezone.utc).isoformat(),'profiles':str(a.profiles),'evidence_inputs':a.evidence,'outputs':{x:str(w/x) for x in ['findings.jsonl','rescored.jsonl','changes.jsonl','cases.json','open-cases.jsonl','monitor.sqlite','associations.jsonl']}}
 (w/'run-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8'); print('pipeline complete: '+str(w))
if __name__=='__main__': main()
