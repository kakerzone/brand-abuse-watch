#!/usr/bin/env python3
"""Create explainable domain-association edges from already collected evidence."""
import argparse, json
from collections import defaultdict

def rows(path):
    with open(path,encoding="utf-8") as f: return [json.loads(x) for x in f if x.strip()]
def values(row):
    for source in row.get("sources",[]):
        data=source.get("data",{}); raw=data.get("raw",{}) if isinstance(data.get("raw"),dict) else {}
        for ip in data.get("addresses",[]): yield "ip",str(ip)
        records=data.get("records",{})
        for ip in records.get("a",[])+records.get("aaaa",[]): yield "ip",str(ip)
        for name in records.get("cname",[]): yield "cname",str(name).rstrip(".").lower()
        for name in records.get("ns",[]): yield "nameserver",str(name).rstrip(".").lower()
        for key,kind in (("favicon_hash","favicon_hash"),("content_hash","content_hash"),("tls_fingerprint","tls_fingerprint"),("certificate_sha256","certificate_sha256")):
            if data.get(key): yield kind,str(data[key])
            if raw.get(key): yield kind,str(raw[key])
        serial=raw.get("serial_number") or raw.get("serial"); issuer=raw.get("issuer_name") or raw.get("issuer")
        if serial and issuer: yield "certificate",str(issuer)+":"+str(serial)
        if source.get("kind")=="rdap":
            for ns in raw.get("nameservers",[]):
                if isinstance(ns,dict) and ns.get("ldhName"): yield "nameserver",str(ns["ldhName"]).rstrip(".").lower()
            for entity in raw.get("entities",[]):
                if "registrar" in entity.get("roles",[]):
                    for item in entity.get("vcardArray",[None,[]])[1]:
                        if isinstance(item,list) and item[0]=="fn": yield "registrar",str(item[3]).lower()
def main():
    p=argparse.ArgumentParser(); p.add_argument("--input",required=True); p.add_argument("--output",required=True); p.add_argument("--min-domains",type=int,default=2); a=p.parse_args(); groups=defaultdict(set)
    for row in rows(a.input):
        if row.get("domain"):
            for kind,value in values(row):
                if value: groups[(kind,value)].add(row["domain"])
    edges=[]
    for (kind,value),domains in sorted(groups.items()):
        if len(domains)>=a.min_domains: edges.append({"indicator_type":kind,"indicator_value":value,"domains":sorted(domains),"domain_count":len(domains),"confidence":"observed_shared_indicator"})
    with open(a.output,"w",encoding="utf-8") as f:
        for edge in edges: f.write(json.dumps(edge,ensure_ascii=False,sort_keys=True)+"\n")
if __name__=="__main__": main()
