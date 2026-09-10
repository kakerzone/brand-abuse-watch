#!/usr/bin/env python3
"""Persist normalized findings/evidence in SQLite for multi-brand retrieval."""
import argparse, json, sqlite3
from pathlib import Path

SCHEMA="""create table if not exists findings (brand_id text not null, domain text not null, brand text, risk_score integer, brand_similarity integer, abuse_likelihood integer, evidence_completeness integer, updated_at text, payload text not null, primary key (brand_id,domain)); create table if not exists evidence (brand_id text not null, domain text not null, kind text not null, collected_at text, payload text not null); create index if not exists evidence_lookup on evidence(kind,domain);"""
def connect(path):
 c=sqlite3.connect(path); c.executescript(SCHEMA); return c
def rows(path):
 with open(path,encoding="utf-8") as f: return [json.loads(x) for x in f if x.strip()]
def main():
 p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
 a=sub.add_parser("import"); a.add_argument("--db",required=True); a.add_argument("--input",required=True)
 a=sub.add_parser("query"); a.add_argument("--db",required=True); a.add_argument("--brand-id"); a.add_argument("--contains"); a.add_argument("--min-score",type=int,default=0); a.add_argument("--limit",type=int,default=100)
 x=p.parse_args(); c=connect(x.db)
 if x.cmd=="import":
  for r in rows(x.input):
   bid=str(r.get("brand_id",r.get("brand","unknown"))); d=r.get("domain")
   if not d: continue
   c.execute("insert into findings values(?,?,?,?,?,?,?,?,?) on conflict(brand_id,domain) do update set brand=excluded.brand,risk_score=excluded.risk_score,brand_similarity=excluded.brand_similarity,abuse_likelihood=excluded.abuse_likelihood,evidence_completeness=excluded.evidence_completeness,updated_at=excluded.updated_at,payload=excluded.payload",(bid,d,r.get("brand"),r.get("risk_score"),r.get("brand_similarity"),r.get("abuse_likelihood"),r.get("evidence_completeness"),r.get("collected_at"),json.dumps(r,ensure_ascii=False)))
   c.execute("delete from evidence where brand_id=? and domain=?",(bid,d))
   for s in r.get("sources",[]): c.execute("insert into evidence values(?,?,?,?,?)",(bid,d,s.get("kind"),s.get("collected_at"),json.dumps(s,ensure_ascii=False)))
  c.commit(); print("imported")
 else:
  where=["risk_score>=?"]; args=[x.min_score]
  if x.brand_id: where.append("brand_id=?"); args.append(x.brand_id)
  if x.contains: where.append("domain like ?"); args.append("%"+x.contains+"%")
  args.append(x.limit)
  for row in c.execute("select payload from findings where "+" and ".join(where)+" order by risk_score desc limit ?",args): print(row[0])
if __name__=="__main__": main()
