# E8CR Squad

[![CI](https://github.com/RADobson/e8cr-squad/actions/workflows/ci.yml/badge.svg)](https://github.com/RADobson/e8cr-squad/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)

**4 specialised OpenClaw agents for Essential Eight ML2 compliance.**

This repo is not just scripts.
It is a full **autonomous agent architecture** where each bot has:
- a role-specific `SOUL.md` (decision style + risk posture)
- `AGENTS.md` (operational doctrine)
- `MEMORY.md` (state, baselines, drift history)
- `TOOLS.md` (script semantics + interpretation)
- `HEARTBEAT.md` (cadence + priorities)
- `SKILL.md` (OpenClaw runtime interface)
- `references/*.md` (ML2 control requirements)

---

## Why this is different

Most "AI security" repos are wrappers around Python scripts.

E8CR is built as **four autonomous OpenClaw operators** with distinct personalities, memory, and operating standards:

1. **VM+PM Bot** — patch applications + patch OS
2. **Identity Bot** — MFA + admin privilege governance
3. **Application Control Bot** — WDAC/macros/hardening
4. **Backup Bot** — backup monitoring + restore assurance

Each bot can reason and operate independently, with its own cadence and escalation logic.

---

## How OpenClaw fits

There are two layers:

1. **OpenClaw autonomy layer (primary)**
   - Reads each bot's `SKILL.md`, `SOUL.md`, `AGENTS.md`, `TOOLS.md`, `MEMORY.md`
   - Decides what to run and when
   - Interprets findings against ML2 requirements
   - Tracks drift over time
   - Escalates based on bot-specific rules

2. **Execution layer (embedded scripts)**
   - Python scripts provide API calls, data collection, and report generation
   - These scripts are implementation details used by the OpenClaw bots

**E8CR is OpenClaw-first and OpenClaw-required.** The scripts exist to serve the agents.

OpenClaw repo: https://github.com/openclaw/openclaw  
OpenClaw docs: https://docs.openclaw.ai/start/getting-started

---

## Bot architecture (what every bot includes)

```
e8cr-<bot>/
├── SKILL.md        # OpenClaw skill definition
├── SOUL.md         # Persona, principles, escalation rules
├── AGENTS.md       # Operating doctrine and cycle
├── MEMORY.md       # State + baselines + findings history
├── TOOLS.md        # Script semantics and interpretation
├── HEARTBEAT.md    # Scheduled check priorities
├── references/     # ML2 requirement references
└── scripts/        # Executable Python tools
```

---

## Quick start (demo, no tenant required)

```bash
git clone https://github.com/RADobson/e8cr-squad.git
cd e8cr-squad

# Run all 4 bots with synthetic data
python3 run_all.py --demo --output ./my-assessment

# Open unified report
open ./my-assessment/e8cr-assessment.html
```

---

## Run as autonomous OpenClaw bots

### Deployment model

Use **one OpenClaw instance per bot** for isolation:
- separate memory/context per control domain
- independent schedules and escalation channels
- lower blast radius on failures
- least-privilege per bot in production

See complete setup: [`examples/openclaw-multi-instance/README.md`](./examples/openclaw-multi-instance/README.md)

---

## Essential Eight ML2 coverage map

| Bot | Controls |
|-----|----------|
| VM+PM | Patch Applications, Patch OS |
| Identity | Multi-factor Authentication, Restrict Administrative Privileges |
| Application Control | Application Control, Configure MS Office Macros, User Application Hardening |
| Backup | Regular Backups |

---

## Safety defaults

Write actions are disabled by default.

```bash
export E8CR_ENABLE_CHANGES=true
```

Only enable after reviewing audit output and rollout plan.

---

## Dependencies

Python 3.10+.
Core scripts use standard library.
Optional Greenbone support:

```bash
pip install -r requirements.txt
```

---

## Project structure

```
e8cr-squad/
├── run_all.py
├── shared/graph_auth.py
├── e8cr-vmpm/
├── e8cr-identity/
├── e8cr-appcontrol/
├── e8cr-backup/
├── examples/openclaw-multi-instance/
├── CONTRIBUTING.md
└── LICENSE
```

---

## What this is not

- Not a one-click compliance certification tool
- Not a substitute for a qualified assessor
- Not a SaaS product

This is an open-source autonomous compliance operator framework.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

[Apache 2.0](./LICENSE)

---

Built by [Richard Dobson](https://dobsondevelopment.com.au) · Powered by [OpenClaw](https://github.com/openclaw/openclaw)
