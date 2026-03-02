# E8CR Squad (Open Source)

Autonomous security/compliance bots aligned to the ACSC Essential Eight.

## What this is
This repository contains the **reference implementation** of the E8CR bots as OpenClaw skills.

Bots included:
- **e8cr-vmpm** — Vulnerability + Patch Management
- **e8cr-identity** — MFA + Admin privilege auditing
- **e8cr-appcontrol** — WDAC, macros, hardening
- **e8cr-backup** — Backup monitoring + restore testing
- **e8cr-edr** — Defender alert triage (note: operational SOC capability; use with care)

## What this is NOT
- Not a turnkey product.
- Not “click once and you’re compliant”.
- Not a substitute for an assessor.

## Security & responsibility
These tools can:
- Call sensitive APIs (Microsoft Graph, Defender, Sentinel)
- Produce highly sensitive outputs (vulnerability lists, admin roles)
- Potentially take response actions (depending on configuration)

**You are responsible for how you run them.** Default to read-only/audit mode until you fully understand the impact.

## Data sovereignty
Designed to run **on-prem**. You can run inference locally (recommended) to avoid sending security data to third-party LLM APIs.

## Quick Start (Demo mode)

This repo includes synthetic demo datasets and HTML reports under [`demo/`](./demo).

To regenerate demo artifacts locally:

```bash
# VM+PM
python3 e8cr-vmpm/scripts/demo_generate.py --output demo/vmpm --full-pipeline

# Identity
python3 e8cr-identity/scripts/demo_generate.py --output demo/identity
python3 e8cr-identity/scripts/generate_report.py --input demo/identity --output demo/identity/identity-report.html

# App Control
python3 e8cr-appcontrol/scripts/demo_generate.py --output demo/appcontrol
python3 e8cr-appcontrol/scripts/generate_report.py --input demo/appcontrol --output demo/appcontrol/appcontrol-report.html

# Backup
python3 e8cr-backup/scripts/demo_generate.py --output demo/backup
python3 e8cr-backup/scripts/generate_report.py --input demo/backup --output demo/backup/backup-report.html

# EDR
python3 e8cr-edr/scripts/demo_generate.py --output demo/edr
python3 e8cr-edr/scripts/generate_report.py --input demo/edr --output demo/edr/edr-report.html
```

Open the HTML reports:
- `demo/vmpm/weekly-report.html`
- `demo/identity/identity-report.html`
- `demo/appcontrol/appcontrol-report.html`
- `demo/backup/backup-report.html`
- `demo/edr/edr-report.html`

## Safe Mode (audit-only by default)

**Write actions are disabled by default.** Any script that can:
- isolate endpoints,
- block IOCs,
- change Defender alert status,
- start vulnerability scans / create Greenbone tasks,

…requires explicit opt-in.

To enable write actions:

```bash
export E8CR_ENABLE_CHANGES=true
```

Strong recommendation: run in audit/report-only mode first, review outputs, then enable changes intentionally.

## Live mode (real tenant)

These bots can be pointed at a real Microsoft tenant using an App Registration:

```bash
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
```

**Be careful:** real tenant runs will generate sensitive outputs (admins, vulnerable devices, etc.).

## License
Apache License 2.0 (see [`LICENSE`](./LICENSE)).

## Contributing
PRs welcome. Keep changes narrowly scoped and well-documented.
