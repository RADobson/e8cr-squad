#!/usr/bin/env python3
import argparse
import os
import re
import sys
try:
    import yaml
except Exception:
    yaml = None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--contract", default="bot.contract.yaml")
    p.add_argument("--root", default=".")
    args = p.parse_args()

    root = os.path.abspath(args.root)
    contract_path = os.path.join(root, args.contract)
    if yaml:
        with open(contract_path) as f:
            c = yaml.safe_load(f)
    else:
        # Minimal fallback parser for this repo's simple YAML structure.
        c = {"required_files": [], "command_registry": {"daily": [], "weekly": []}}
        section = None
        sub = None
        with open(contract_path) as f:
            for raw in f:
                line = raw.rstrip("\n")
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.startswith("required_files:"):
                    section = "required_files"; sub = None; continue
                if s.startswith("command_registry:"):
                    section = "command_registry"; sub = None; continue
                if section == "command_registry" and s.startswith("daily:"):
                    sub = "daily"; continue
                if section == "command_registry" and s.startswith("weekly:"):
                    sub = "weekly"; continue
                if s.startswith("- ") and section == "required_files":
                    c["required_files"].append(s[2:].strip())
                if s.startswith("- ") and section == "command_registry" and sub:
                    c["command_registry"][sub].append(s[2:].strip())

    errors = []

    for rf in c.get("required_files", []):
        if not os.path.exists(os.path.join(root, rf)):
            errors.append(f"Missing required file: {rf}")

    skill = open(os.path.join(root, "SKILL.md")).read()
    hb = open(os.path.join(root, "HEARTBEAT.md")).read()

    for period, cmds in c.get("command_registry", {}).items():
        for cmd in cmds:
            m = re.search(r"scripts/([\w_\-]+\.py)", cmd)
            if m and not os.path.exists(os.path.join(root, "scripts", m.group(1))):
                errors.append(f"Command references missing script: {cmd}")
            if m and m.group(1) not in skill:
                errors.append(f"Script not referenced in SKILL.md: {m.group(1)}")
            if period in ("daily", "weekly") and m:
                if (m.group(1) not in hb) and ("run_cycle.py" not in hb):
                    errors.append(f"Script not referenced in HEARTBEAT.md: {m.group(1)}")

    if errors:
        for e in errors:
            print(f"ERROR: {e}")
        sys.exit(1)

    print("Contract consistency OK")


if __name__ == "__main__":
    main()
