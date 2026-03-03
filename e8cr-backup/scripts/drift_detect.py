#!/usr/bin/env python3
import argparse,json,os,hashlib
from datetime import datetime,timezone

def load(p,d):
  if not os.path.exists(p): return d
  with open(p) as f: return json.load(f)

def fp(obj):
  return hashlib.sha256(json.dumps(obj,sort_keys=True).encode()).hexdigest()

def main():
  p=argparse.ArgumentParser(); p.add_argument('--current-dir',required=True); p.add_argument('--state-file',required=True); p.add_argument('--output',required=True); a=p.parse_args()
  files=[f for f in os.listdir(a.current_dir) if f.endswith('.json') and f not in ('drift.json',)]
  cur={"generated_at":datetime.now(timezone.utc).isoformat(),"fingerprint":{},"exceptions":[]}
  for fn in sorted(files):
    data=load(os.path.join(a.current_dir,fn),{})
    cur['fingerprint'][fn]=fp(data)
    txt=json.dumps(data).lower()
    if any(k in txt for k in ['exception','exclude','exclusion','allow all']): cur['exceptions'].append(fn)
  prev=load(a.state_file,{"fingerprint":{},"exceptions":[]})
  deleted=sorted(set(prev.get('fingerprint',{}))-set(cur['fingerprint']))
  changed=sorted([k for k,v in cur['fingerprint'].items() if prev.get('fingerprint',{}).get(k) and prev['fingerprint'][k]!=v])
  new_ex=sorted(set(cur.get('exceptions',[]))-set(prev.get('exceptions',[])))
  sev,reason='P3','No material drift detected'
  if deleted: sev,reason='P1','Evidence/profile deletion detected'
  elif changed or new_ex: sev,reason='P2','Evidence or exception drift detected'
  out={"has_drift":bool(deleted or changed or new_ex),"severity":sev,"escalation_reason":reason,"summary":{"profiles_deleted":deleted,"assignment_changes":changed,"new_exclusions_or_exceptions":new_ex},"current_snapshot":cur}
  os.makedirs(os.path.dirname(a.output) or '.',exist_ok=True)
  with open(a.output,'w') as f: json.dump(out,f,indent=2)
  os.makedirs(os.path.dirname(a.state_file) or '.',exist_ok=True)
  with open(a.state_file,'w') as f: json.dump(cur,f,indent=2)
  print(json.dumps({"status":"ok","drift":out['has_drift'],"severity":sev}))
if __name__=='__main__': main()
