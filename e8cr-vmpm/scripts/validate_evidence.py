#!/usr/bin/env python3
import argparse,json,os,sys
try:
  from jsonschema import validate as _validate
except Exception:
  _validate=None

def main():
  p=argparse.ArgumentParser(); p.add_argument('--evidence-dir',required=True); p.add_argument('--schemas-dir',required=True); a=p.parse_args()
  for sf in os.listdir(a.schemas_dir):
    if not sf.endswith('.schema.json'): continue
    df=sf.replace('.schema.json','.json')
    dp=os.path.join(a.evidence_dir,df)
    if not os.path.exists(dp): continue
    data=json.load(open(dp)); schema=json.load(open(os.path.join(a.schemas_dir,sf)))
    if _validate: _validate(instance=data,schema=schema)
    else:
      for req in schema.get('required',[]):
        if req not in data: raise ValueError(f"{df}: missing required key '{req}'")
    print(f'Validated {df}')
if __name__=='__main__':
  try: main()
  except Exception as e: print(f'Validation failed: {e}'); sys.exit(1)
