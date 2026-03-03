#!/usr/bin/env python3
import argparse,json,os,subprocess,sys
from datetime import datetime, timezone
SCRIPT_DIR=os.path.dirname(os.path.abspath(__file__))
ROOT_DIR=os.path.abspath(os.path.join(SCRIPT_DIR,'..'))
SHARED_DIR=os.path.abspath(os.path.join(SCRIPT_DIR,'..','..','shared'))

def run(cmd, env=None):
  r=subprocess.run(cmd,capture_output=True,text=True,env=env)
  return {'cmd':' '.join(cmd),'returncode':r.returncode,'stdout':r.stdout[-500:],'stderr':r.stderr[-500:]}

def load_json(path, default):
  if not os.path.exists(path):
    return default
  with open(path) as f:
    return json.load(f)

def save_json(path, obj):
  os.makedirs(os.path.dirname(path), exist_ok=True)
  with open(path,'w') as f:
    json.dump(obj,f,indent=2)

def main():
  p=argparse.ArgumentParser()
  p.add_argument('--period',choices=['daily','weekly'],required=True)
  p.add_argument('--demo',action='store_true')
  p.add_argument('--incremental',action='store_true',help='Use last successful cycle timestamp as delta marker')
  p.add_argument('--output-root',default=os.path.join(ROOT_DIR,'evidence'))
  p.add_argument('--state-file',default=os.path.join(ROOT_DIR,'state','last_snapshot.json'))
  p.add_argument('--cycle-state-file',default=os.path.join(ROOT_DIR,'state','cycle_state.json'))
  p.add_argument('--memory-file',default=os.path.join(ROOT_DIR,'MEMORY.md'))
  p.add_argument('--update-memory',action='store_true')
  p.add_argument('--date')
  a=p.parse_args()
  date=a.date or datetime.now().strftime('%Y-%m-%d')
  out=os.path.join(a.output_root,date)
  os.makedirs(out,exist_ok=True)

  cycle_state=load_json(a.cycle_state_file,{'last_success_at':None})
  since=cycle_state.get('last_success_at') if a.incremental else None

  steps=[]
  if a.demo:
    steps=[[sys.executable,os.path.join(SCRIPT_DIR,'demo_generate.py'),'--output',out,'--full-pipeline']]
  else:
    daily=['python3 scripts/provider_dispatch.py --mode fetch-jobs > {out}/backup-jobs.json', 'python3 scripts/backup_jobs.py --mode audit --provider all > {out}/backup-jobs-audit.json']
    weekly=['python3 scripts/demo_generate.py --output {out}', 'python3 scripts/generate_report.py --input {out} --output {out}/backup-report.html']
    env=dict(os.environ)
    if since:
      env['E8CR_SINCE']=since
    for cmd in daily + (weekly if a.period=='weekly' else []):
      steps.append((['bash','-lc',cmd.replace('{out}',out)], env))

  results=[]
  if a.demo:
    results=[run(s) for s in steps]
  else:
    for s,env in steps:
      results.append(run(s,env=env))
  ok=all(r['returncode']==0 for r in results)

  if ok and not a.demo:
    results.append(run([sys.executable,os.path.join(SCRIPT_DIR,'drift_detect.py'),'--current-dir',out,'--state-file',a.state_file,'--output',os.path.join(out,'drift.json')]))

  if ok:
    results.append(run([sys.executable,os.path.join(SHARED_DIR,'evidence_pack.py'),'--input-dir',out,'--period',a.period]))

  if ok and a.update_memory:
    results.append(run([sys.executable,os.path.join(SCRIPT_DIR,'update_memory.py'),'--memory',a.memory_file,'--drift',os.path.join(out,'drift.json'),'--evidence-dir',out]))

  ok=all(r['returncode']==0 for r in results)
  if ok and not a.demo:
    cycle_state['last_success_at']=datetime.now(timezone.utc).isoformat()
    save_json(a.cycle_state_file,cycle_state)

  print(json.dumps({'status':'ok' if ok else 'failed','period':a.period,'output_dir':out,'incremental':bool(a.incremental),'since':since,'steps':results},indent=2))
  raise SystemExit(0 if ok else 2)
if __name__=='__main__':
  main()
