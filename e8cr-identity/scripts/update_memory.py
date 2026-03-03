#!/usr/bin/env python3
import argparse,json,os
from datetime import datetime

def load(p,d):
  if not os.path.exists(p): return d
  with open(p) as f: return json.load(f)

def main():
  p=argparse.ArgumentParser(); p.add_argument('--memory',required=True); p.add_argument('--drift',required=True); p.add_argument('--evidence-dir',required=True); a=p.parse_args()
  drift=load(a.drift,{"severity":"P3","escalation_reason":"No drift"})
  stamp=datetime.now().strftime('%Y-%m-%d %H:%M AEST')
  section=f"""
### {stamp} — Automated cycle update
- Severity: {drift.get('severity','P3')}
- Escalation reason: {drift.get('escalation_reason','')}
- Drift: {'yes' if drift.get('has_drift') else 'no'}
"""
  with open(a.memory,'a') as f: f.write('
'+section+'
')
  print('{"status":"ok"}')
if __name__=='__main__': main()
