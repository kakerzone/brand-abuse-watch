#!/usr/bin/env python3
"""Validate multi-brand profile shape without making network requests."""
import argparse, json, sys
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec

spec=spec_from_file_location("parser",Path(__file__).with_name("parse_evidence.py")); parser=module_from_spec(spec); spec.loader.exec_module(parser)
def check(path, ids):
    errors=[]; warnings=[]
    try: p=json.loads(path.read_text(encoding="utf-8"))
    except Exception as e: return [f"{path}: invalid JSON: {e}"],[]
    for key in ("brand_id","brand","official_domains"):
        if not p.get(key): errors.append(f"{path}: missing {key}")
    if p.get("brand_id") in ids: errors.append(f"{path}: duplicate brand_id {p['brand_id']}")
    ids.add(p.get("brand_id"))
    bad=[x for x in p.get("official_domains",[]) if not parser.canon(x)]
    if bad: errors.append(f"{path}: invalid official_domains: {', '.join(map(str,bad))}")
    if not p.get("aliases"): warnings.append(f"{path}: no aliases configured")
    if not any(p.get("risk_keywords",{}).values()): warnings.append(f"{path}: no risk keywords configured")
    if not p.get("allowlist"): warnings.append(f"{path}: no allowlist configured")
    return errors,warnings
def main():
    a=argparse.ArgumentParser(); a.add_argument("--profiles",required=True); x=a.parse_args(); ids=set(); errors=[]; warnings=[]
    files=sorted(Path(x.profiles).glob("*.json"))
    if not files: errors.append("no JSON profiles found")
    for f in files:
        e,w=check(f,ids); errors+=e; warnings+=w
    for x in warnings: print("WARNING: "+x)
    for x in errors: print("ERROR: "+x,file=sys.stderr)
    if errors: sys.exit(1)
    print(f"OK: validated {len(files)} profiles")
if __name__=="__main__": main()
