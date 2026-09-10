#!/usr/bin/env python3
"""Generate a local review package; it never submits a takedown request."""
import argparse,json
from pathlib import Path
def main():
 p=argparse.ArgumentParser(); p.add_argument('--finding',required=True); p.add_argument('--case',required=True); p.add_argument('--output',required=True); a=p.parse_args()
 finding=json.loads(Path(a.finding).read_text()); case=json.loads(Path(a.case).read_text()); out=Path(a.output); out.mkdir(parents=True,exist_ok=True)
 (out/'finding.json').write_text(json.dumps(finding,ensure_ascii=False,indent=2),encoding='utf-8'); (out/'case.json').write_text(json.dumps(case,ensure_ascii=False,indent=2),encoding='utf-8')
 lines=['# Brand impersonation evidence package','',f"- Domain: `{finding.get('domain')}`",f"- Brand: {finding.get('brand')}",f"- Case: `{case.get('case_id')}` ({case.get('status')})",f"- Priority: {finding.get('risk_score')}",'','## Evidence sources']
 lines += [f"- {s.get('kind')} — {s.get('status')} — {s.get('collected_at')}" for s in finding.get('sources',[])] or ['- None']
 lines += ['','## Boundary','This package is an internal review artifact. It is not proof of wrongdoing and must be human-reviewed before any report, block, or takedown action.']
 (out/'README.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
if __name__=='__main__': main()
