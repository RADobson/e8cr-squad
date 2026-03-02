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

## License
TBD (choose one): MIT / Apache-2.0

## Contributing
PRs welcome. Keep changes narrowly scoped and well-documented.
