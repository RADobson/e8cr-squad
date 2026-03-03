#!/usr/bin/env python3
import argparse,json,os,subprocess,sys
from datetime import datetime
SCRIPT_DIR=os.path.dirname(os.path.abspath(__file__))
ROOT_DIR=os.path.abspath(os.path.join(SCRIPT_DIR,'..'))

def run(cmd):
  r=subprocess.run(cmd,capture_output=True,text=True)
  return {'cmd':' '.join(cmd),'returncode':r.returncode,'stdout':r.stdout[-500:],'stderr':r.stderr[-500:]}

def main():
  p=argparse.ArgumentParser(); p.add_argument('--period',choices=['daily','weekly'],required=True); p.add_argument('--demo',action='store_true'); p.add_argument('--output-root',default=os.path.join(ROOT_DIR,'evidence')); p.add_argument('--state-file',default=os.path.join(ROOT_DIR,'state','last_snapshot.json')); p.add_argument('--memory-file',default=os.path.join(ROOT_DIR,'MEMORY.md')); p.add_argument('--update-memory',action='store_true'); p.add_argument('--date'); a=p.parse_args()
  date=a.date or datetime.now().strftime('%Y-%m-%d'); out=os.path.join(a.output_root,date); os.makedirs(out,exist_ok=True)
  steps=[]
  if a.demo:
    steps=[[sys.executable,os.path.join(SCRIPT_DIR,'demo_generate.py'),'--output',out,'--full-pipeline']]
  else:
    daily=['python3 scripts/graph_patches.py --action compliance-report > {out}/patch-compliance.json', 'python3 scripts/graph_mdvm.py --action scan > {out}/scan-results.json']; weekly=['python3 scripts/vuln_prioritise.py --results-file {out}/scan-results.json --output {out}/prioritised.json', 'python3 scripts/generate_report.py --type weekly --patch-data {out}/patch-compliance.json --vuln-data {out}/prioritised.json --output {out}/weekly-report.html']
    for c in daily+(weekly if a.period=='weekly' else []):
      steps.append(['bash','-lc',c.replace('{out}',out)])
  results=[run(s) for s in steps]; ok=all(r['returncode']==0 for r in results)
  if ok and not a.demo:
    results.append(run([sys.executable,os.path.join(SCRIPT_DIR,'drift_detect.py'),'--current-dir',out,'--state-file',a.state_file,'--output',os.path.join(out,'drift.json')]))
  if ok and a.update_memory:
    results.append(run([sys.executable,os.path.join(SCRIPT_DIR,'update_memory.py'),'--memory',a.memory_file,'--drift',os.path.join(out,'drift.json'),'--evidence-dir',out]))
  ok=all(r['returncode']==0 for r in results)
  print(json.dumps({'status':'ok' if ok else 'failed','period':a.period,'output_dir':out,'steps':results},indent=2))
  raise SystemExit(0 if ok else 2)
if __name__=='__main__': main()
