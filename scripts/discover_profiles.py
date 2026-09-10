#!/usr/bin/env python3
"""Run offline candidate discovery for every JSON brand profile in a directory."""
import argparse, importlib.util, json
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("brand_monitor",HERE/"brand_monitor.py")
monitor=importlib.util.module_from_spec(spec); spec.loader.exec_module(monitor)
def main():
    p=argparse.ArgumentParser(); p.add_argument("--profiles",required=True); p.add_argument("--output",required=True)
    a=p.parse_args(); rows=[]
    for profile_file in sorted(Path(a.profiles).glob("*.json")):
        profile=json.loads(profile_file.read_text(encoding="utf-8")); rows.extend(monitor.discover(profile))
    monitor.write_jsonl(a.output,rows)
if __name__=="__main__": main()
