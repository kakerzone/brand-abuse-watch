#!/usr/bin/env python3
"""Export association JSONL as a reviewable Graphviz DOT graph."""
import argparse,json
def q(s): return '"'+str(s).replace('"','\\"')+'"'
def main():
 p=argparse.ArgumentParser(); p.add_argument('--input',required=True); p.add_argument('--output',required=True); a=p.parse_args()
 lines=['graph associations {','  rankdir=LR;']
 for line in open(a.input,encoding='utf-8'):
  if not line.strip(): continue
  e=json.loads(line); ind=e['indicator_type']+':'+e['indicator_value']; lines.append('  '+q(ind)+' [shape=box];')
  for d in e['domains']: lines.append('  '+q(d)+' -- '+q(ind)+';')
 lines.append('}')
 open(a.output,'w',encoding='utf-8').write('\n'.join(lines)+'\n')
if __name__=='__main__': main()
