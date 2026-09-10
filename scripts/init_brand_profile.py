#!/usr/bin/env python3
"""Create a review-required brand profile from name, official URL(s), and local logo."""
import argparse, hashlib, json, re
from pathlib import Path
from urllib.parse import urlparse

def host(value):
    raw=value if '://' in value else 'https://'+value
    h=(urlparse(raw).hostname or '').lower().rstrip('.')
    try: h=h.encode('idna').decode('ascii')
    except UnicodeError: return None
    return h if '.' in h else None
def alias(text): return re.sub(r'[^a-z0-9]+','',text.lower())
def visual(path):
    from PIL import Image
    raw=Path(path).read_bytes(); image=Image.open(path); image.load(); px=list(image.convert('L').resize((17,16)).getdata())
    dhash=format(sum((1<<i) for i in range(16) for x in range(16) if px[i*17+x]>px[i*17+x+1]),'x')
    return {'sha256':hashlib.sha256(raw).hexdigest(),'dhash':dhash,'max_distance':12,'source':'local_logo'}
def main():
    p=argparse.ArgumentParser(); p.add_argument('--name'); p.add_argument('--brand-id'); p.add_argument('--website',action='append',default=[]); p.add_argument('--logo'); p.add_argument('--alias',action='append',default=[]); p.add_argument('--risk-keyword',action='append',default=[]); p.add_argument('--output',required=True); a=p.parse_args()
    domains=[host(x) for x in a.website]; domains=[x for x in domains if x]
    if not a.name and not domains: p.error('provide --name or at least one --website')
    name=a.name or domains[0].split('.')[0]
    default_id=alias(name) or domains[0].split('.')[0]
    # A www host is a transport prefix, never a brand alias. Including it would
    # create unrelated candidates such as "casino-www.com".
    domain_labels={(x.split('.')[0] if x.split('.')[0] != 'www' else x.split('.')[1]) for x in domains if len(x.split('.')) >= 2}
    aliases={alias(name),*(alias(x) for x in a.alias),*domain_labels}-{''}
    profile={'brand_id':a.brand_id or default_id,'brand':name,'official_domains':domains,'official_ips':[],'official_visual_hashes':[],'aliases':sorted(aliases),'brand_terms':[name],'tlds':['com','net','org','io','co'],'risk_keywords':{'high':sorted(set(a.risk_keyword)),'phishing':[]},'allowlist':domains,'max_candidates':500,'profile_notes':['Review aliases, TLDs, risk keywords, official IPs, and visual hashes before operational use.']}
    if a.logo:
        try: profile['official_visual_hashes'].append(visual(a.logo))
        except Exception as e: p.error('local logo could not be fingerprinted: '+str(e))
    Path(a.output).write_text(json.dumps(profile,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print('created review-required profile: '+a.output)
if __name__=='__main__': main()
