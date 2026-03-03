#!/usr/bin/env python3
import argparse
import json
import os
import sys

try:
    from jsonschema import validate as _jsonschema_validate
except Exception:
    _jsonschema_validate = None


MAPPING = {
    "appcontrol-audit.json": "appcontrol-audit.schema.json",
    "macro-audit.json": "macro-audit.schema.json",
    "hardening-audit.json": "hardening-audit.schema.json",
    "drift.json": "drift.schema.json",
}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence-dir", required=True)
    p.add_argument("--schemas-dir", required=True)
    args = p.parse_args()

    for data_file, schema_file in MAPPING.items():
        dp = os.path.join(args.evidence_dir, data_file)
        if not os.path.exists(dp):
            continue
        sp = os.path.join(args.schemas_dir, schema_file)
        with open(dp) as f:
            data = json.load(f)
        with open(sp) as f:
            schema = json.load(f)

        if _jsonschema_validate:
            _jsonschema_validate(instance=data, schema=schema)
        else:
            # Lightweight fallback: enforce top-level required keys only.
            for req in schema.get("required", []):
                if req not in data:
                    raise ValueError(f"{data_file}: missing required key '{req}'")

        print(f"Validated {data_file}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Validation failed: {e}")
        sys.exit(1)
