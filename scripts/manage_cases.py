#!/usr/bin/env python3
"""Maintain auditable internal review state for brand-monitor findings."""
import argparse, json, sys
from datetime import datetime, timezone
from pathlib import Path

NOW=lambda: datetime.now(timezone.utc).isoformat()
STATUS={"new","triaged","confirmed_impersonation","false_positive","ignored","takedown_pending","resolved"}
TRANSITIONS={"new":{"triaged","confirmed_impersonation","false_positive","ignored"},"triaged":{"confirmed_impersonation","false_positive","ignored","takedown_pending"},"confirmed_impersonation":{"takedown_pending","resolved"},"takedown_pending":{"resolved"},"false_positive":set(),"ignored":set(),"resolved":set()}
def load(path,default): return json.loads(Path(path).read_text()) if Path(path).exists() else default
def save(path,value): Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True),encoding="utf-8")
def key(row): return f"{row.get('brand_id',row.get('brand','unknown'))}:{row['domain']}"
def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("sync"); a.add_argument("--input",required=True); a.add_argument("--state",required=True); a.add_argument("--min-score",type=int,default=40); a.add_argument("--worklist",required=True)
    a=sub.add_parser("set-status"); a.add_argument("--state",required=True); a.add_argument("--case",required=True); a.add_argument("--status",required=True,choices=sorted(STATUS)); a.add_argument("--note",required=True); a.add_argument("--actor",required=True)
    a=sub.add_parser("list"); a.add_argument("--state",required=True); a.add_argument("--status",choices=sorted(STATUS))
    a=p.parse_args(); state=load(a.state,{"cases":{}})
    if a.cmd=="sync":
        rows=[]
        with open(a.input,encoding="utf-8") as f: rows=[json.loads(x) for x in f if x.strip()]
        for row in rows:
            if row.get("risk_score",0)<a.min_score: continue
            k=key(row); case=state["cases"].setdefault(k,{"case_id":k,"brand_id":row.get("brand_id"),"domain":row["domain"],"status":"new","created_at":NOW(),"history":[]})
            case.update({"risk_score":row.get("risk_score"),"brand_similarity":row.get("brand_similarity"),"abuse_likelihood":row.get("abuse_likelihood"),"evidence_completeness":row.get("evidence_completeness"),"last_seen":NOW()})
        save(a.state,state)
        with open(a.worklist,"w",encoding="utf-8") as f:
            for x in sorted(state["cases"].values(),key=lambda y:-y.get("risk_score",0)):
                if x["status"] in {"new","triaged","confirmed_impersonation","takedown_pending"}: f.write(json.dumps(x,ensure_ascii=False,sort_keys=True)+"\n")
    elif a.cmd=="set-status":
        case=state["cases"].get(a.case)
        if not case: sys.exit("error: unknown case")
        old=case["status"]
        if a.status!=old and a.status not in TRANSITIONS[old]: sys.exit(f"error: {old} cannot transition to {a.status}")
        case["status"]=a.status; case["history"].append({"at":NOW(),"actor":a.actor,"from":old,"to":a.status,"note":a.note}); save(a.state,state)
    else:
        for x in state["cases"].values():
            if not a.status or x["status"]==a.status: print(json.dumps(x,ensure_ascii=False))
if __name__=="__main__": main()
