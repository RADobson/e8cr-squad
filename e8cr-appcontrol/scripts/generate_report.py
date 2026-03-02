#!/usr/bin/env python3
"""Generate HTML report for Application Control bot evidence pack."""

import os
import json
import argparse
from datetime import datetime


def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def render_summary(app, macro, hard):
    a = app.get("appcontrol_policies_found", 0)
    m = macro.get("macro_policies_found", 0)
    h = hard.get("hardening_policies_found", 0)
    return f"""
    <ul>
      <li>Application control policies found: <b>{a}</b></li>
      <li>Macro control policies found: <b>{m}</b></li>
      <li>Hardening policies found: <b>{h}</b></li>
    </ul>
    """


def html_page(title, body):
    return f"""<!doctype html>
<html><head><meta charset='utf-8'><title>{title}</title>
<style>body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;line-height:1.5}}pre{{background:#111;color:#eee;padding:12px;overflow:auto}}.muted{{color:#666}}</style>
</head><body>
<h1>{title}</h1>
<p class='muted'>Generated {datetime.now().isoformat(timespec='seconds')}</p>
{body}
</body></html>"""


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="Directory containing appcontrol-audit.json, macro-audit.json, hardening-audit.json")
    p.add_argument("--output", required=True)
    args = p.parse_args()

    app = load_json(os.path.join(args.input, "appcontrol-audit.json"))
    macro = load_json(os.path.join(args.input, "macro-audit.json"))
    hard = load_json(os.path.join(args.input, "hardening-audit.json"))

    body = "<h2>Executive Summary</h2>" + render_summary(app, macro, hard)
    body += "<h2>Application Control Audit</h2><pre>" + json.dumps(app, indent=2) + "</pre>"
    body += "<h2>Macro Settings Audit</h2><pre>" + json.dumps(macro, indent=2) + "</pre>"
    body += "<h2>User Application Hardening Audit</h2><pre>" + json.dumps(hard, indent=2) + "</pre>"

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(html_page("E8CR Application Control Evidence Report", body))
    print(args.output)


if __name__ == "__main__":
    main()
