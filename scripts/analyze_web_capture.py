#!/usr/bin/env python3
"""Analyze a locally captured HTML page; no network access or JavaScript execution."""
import argparse, hashlib, json, re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

NOW=lambda: datetime.now(timezone.utc).isoformat()
class Capture(HTMLParser):
    def __init__(self): super().__init__(); self.title=[]; self.text=[]; self.in_title=False; self.forms=[]; self.current=None; self.images=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=="title": self.in_title=True
        elif tag=="form": self.current={"action":a.get("action"),"method":a.get("method","get").lower(),"inputs":[]}; self.forms.append(self.current)
        elif tag=="input" and self.current is not None: self.current["inputs"].append({"type":a.get("type","text").lower(),"name":a.get("name"),"placeholder":a.get("placeholder")})
        elif tag=="img": self.images.append({"src":a.get("src"),"alt":a.get("alt")})
    def handle_endtag(self,tag):
        if tag=="title": self.in_title=False
        elif tag=="form": self.current=None
    def handle_data(self,data):
        if self.in_title: self.title.append(data)
        self.text.append(data)
def simhash(text):
    weights=[0]*64
    for token in re.findall(r"[\w-]{3,}",text.lower()):
        n=int.from_bytes(hashlib.sha256(token.encode()).digest()[:8],"big")
        for i in range(64): weights[i]+=1 if n>>i&1 else -1
    return format(sum((1<<i) for i,w in enumerate(weights) if w>=0),"016x")
def main():
    p=argparse.ArgumentParser(); p.add_argument("--domain",required=True); p.add_argument("--html",required=True); p.add_argument("--profile",required=True); p.add_argument("--output",required=True); a=p.parse_args()
    raw=Path(a.html).read_bytes(); profile=json.loads(Path(a.profile).read_text(encoding="utf-8")); page=Capture(); page.feed(raw.decode("utf-8","replace"))
    title=re.sub(r"\s+"," "," ".join(page.title)).strip()[:300]; text=re.sub(r"\s+"," "," ".join(page.text)).strip()
    terms={str(profile.get("brand","")).lower(),*(str(x).lower() for x in profile.get("aliases",[])),*(str(x).lower() for x in profile.get("brand_terms",[]))}-{''}
    hits=sorted(x for x in terms if x in text.lower() or x in title.lower())
    credential=any(any(i["type"]=="password" for i in f["inputs"]) for f in page.forms)
    payment_words={"card","cvv","iban","wallet","payment","withdraw","deposit","bank"}
    payment=any(any((i.get("name") or "").lower() in payment_words or (i.get("placeholder") or "").lower() in payment_words for i in f["inputs"]) for f in page.forms)
    evidence={"content_sha256":hashlib.sha256(raw).hexdigest(),"text_simhash":simhash(text),"title":title,"brand_mentions":hits,"forms":page.forms,"credential_form":credential,"payment_form":payment,"images":page.images[:50],"capture_mode":"offline_html_only"}
    status="ok" if raw else "unavailable"
    row={"domain":a.domain.lower().rstrip("."),"collected_at":NOW(),"sources":[{"kind":"web_capture","collected_at":NOW(),"status":status,"data":evidence}]}
    Path(a.output).write_text(json.dumps(row,ensure_ascii=False,sort_keys=True)+"\n",encoding="utf-8")
if __name__=="__main__": main()
