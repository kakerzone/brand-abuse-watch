#!/usr/bin/env python3
"""Generate offline, explainable screenshot/favicon fingerprints using Pillow."""
import argparse, hashlib, json
from datetime import datetime, timezone
from pathlib import Path

NOW=lambda: datetime.now(timezone.utc).isoformat()
def bits(values): return format(sum((1<<i) for i,v in enumerate(values) if v),"x")
def ahash(image):
    px=list(image.convert("L").resize((16,16)).getdata()); avg=sum(px)/len(px); return bits([x>=avg for x in px])
def dhash(image):
    px=list(image.convert("L").resize((17,16)).getdata()); return bits([px[y*17+x]>px[y*17+x+1] for y in range(16) for x in range(16)])
def hamming(a,b): return (int(a,16)^int(b,16)).bit_count()
def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("fingerprint"); a.add_argument("--domain",required=True); a.add_argument("--image",required=True); a.add_argument("--kind",choices=("screenshot","favicon","logo"),required=True); a.add_argument("--output",required=True)
    a=sub.add_parser("compare"); a.add_argument("--left",required=True); a.add_argument("--right",required=True); a.add_argument("--output",required=True)
    x=p.parse_args()
    if x.cmd=="fingerprint":
        try:
            from PIL import Image
            raw=Path(x.image).read_bytes(); image=Image.open(x.image); image.load()
        except Exception as e: raise SystemExit("error: Pillow readable image required: "+str(e))
        data={"kind":x.kind,"sha256":hashlib.sha256(raw).hexdigest(),"ahash":ahash(image),"dhash":dhash(image),"width":image.width,"height":image.height,"capture_mode":"offline_image_only"}
        row={"domain":x.domain.lower().rstrip("."),"collected_at":NOW(),"sources":[{"kind":"visual_fingerprint","collected_at":NOW(),"status":"ok","data":data}]}
    else:
        left=json.loads(Path(x.left).read_text(encoding="utf-8")); right=json.loads(Path(x.right).read_text(encoding="utf-8"))
        l=left["sources"][0]["data"]; r=right["sources"][0]["data"]
        row={"left_domain":left["domain"],"right_domain":right["domain"],"ahash_distance":hamming(l["ahash"],r["ahash"]),"dhash_distance":hamming(l["dhash"],r["dhash"]),"exact_file_match":l["sha256"]==r["sha256"],"note":"Lower perceptual-hash distance indicates greater visual similarity; review images manually."}
    Path(x.output).write_text(json.dumps(row,ensure_ascii=False,sort_keys=True)+"\n",encoding="utf-8")
if __name__=="__main__": main()
