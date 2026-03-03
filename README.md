# E8CR Squad

[![CI](https://github.com/RADobson/e8cr-squad/actions/workflows/ci.yml/badge.svg)](https://github.com/RADobson/e8cr-squad/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)

**4 autonomous AI agents that implement Essential Eight ML2 compliance on your hardware.**

E8CR Squad covers all 8 controls of the [Australian Government Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) at Maturity Level 2. The agents scan your Microsoft 365 tenant, enforce policies, generate audit-ready evidence, and produce compliance reports — continuously, without human intervention.

Everything runs on-prem. Your security data never leaves your network.

---

## How it works

E8CR Squad has two layers:

1. **Python scripts** — the tools that talk to Microsoft Graph API, Greenbone, Veeam, etc. These do the actual scanning, querying, and reporting. You can run them standalone from the command line.

2. **[OpenClaw](https://github.com/openclaw/openclaw)** — the AI brain. OpenClaw is an open-source personal AI assistant framework. It reads each bot's `SKILL.md` file, which tells it what scripts are available, when to run them, and how to interpret the results. OpenClaw is what makes the bots *autonomous* — it decides what to check, runs the right scripts, reasons about the output, and takes action.

**Without OpenClaw**, you have a useful set of compliance scripts you run manually.  
**With OpenClaw**, you have autonomous agents that work 24/7 without being told what to do.

```
┌─────────────────────────────────────────────────────┐
│  Your hardware (Mac Mini, Linux box, or any server) │
│                                                     │
│  ┌─────────────┐  ┌─────────────┐                   │
│  │  OpenClaw    │  │  OpenClaw    │  ... (one per    │
│  │  instance    │  │  instance    │      bot)        │
│  │             │  │             │                   │
│  │  SKILL.md   │  │  SKILL.md   │  ← tells the AI  │
│  │  (vmpm)     │  │  (identity) │    what to do     │
│  │             │  │             │                   │
│  │  scripts/   │  │  scripts/   │  ← Python tools   │
│  │  *.py       │  │  *.py       │    it can call    │
│  └──────┬──────┘  └──────┬──────┘                   │
│         │                │                          │
│         └────────┬───────┘                          │
│                  │                                  │
│         shared/graph_auth.py                        │
│    (client credentials → Graph token)               │
└──────────────────┬──────────────────────────────────┘
                   │
     ┌─────────────┴─────────────┐
     ▼                           ▼
Microsoft Graph API        Greenbone/OpenVAS
(Intune, Entra ID)         (optional vuln scanner)
```

Each bot runs as a **separate OpenClaw instance** with its own workspace. This keeps them isolated — each bot has its own memory, its own schedule, and its own scope of access.

---

## The 4 bots

| Bot | E8 Controls | What it does | Integrations |
|-----|-------------|-------------|-------------|
| **VM+PM** | Patch Applications, Patch OS | Finds vulnerabilities, prioritises by real-world exploitability (CISA KEV + EPSS), orchestrates patching, verifies fixes, produces evidence | Intune, Greenbone/OpenVAS, MDVM |
| **Identity** | MFA, Restrict Admin Privileges | Enforces MFA, audits admin roles, monitors Conditional Access, detects legacy auth and privilege creep | Microsoft Entra ID |
| **Application Control** | Application Control, Office Macros, User App Hardening | Manages WDAC policies, macro restrictions, browser hardening. Audit mode first, enforce when ready | Intune |
| **Backup** | Regular Backups | Monitors backup jobs, identifies coverage gaps, runs restore tests, proves backups actually work | Veeam B&R, Azure Backup |

---

## Try it now (demo mode)

No tenant, no OpenClaw, no setup. Just Python 3.10+.

```bash
git clone https://github.com/RADobson/e8cr-squad.git
cd e8cr-squad

# Run all 4 bots with synthetic data
python3 run_all.py --demo --output ./my-assessment

# Open the unified compliance dashboard
open ./my-assessment/e8cr-assessment.html
```

This generates a complete ML2 compliance report: unified dashboard with compliance score, per-bot reports, and JSON evidence files.

```bash
# Custom company name
python3 run_all.py --demo --company "Acme Corp" --output ./report

# Run specific bots only
python3 run_all.py --demo --bots vmpm identity --output ./partial
```

---

## Setup: standalone scripts (no OpenClaw)

If you just want to run the scripts manually against your tenant:

### 1. Create an App Registration in Entra ID

Azure Portal → Entra ID → App registrations → New registration.

Grant these **Application** permissions (not Delegated) and admin consent:

| Bot | Permissions |
|-----|------------|
| vmpm | `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `Vulnerability.Read.All`, `Software.Read.All` |
| identity | `User.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.All`, `UserAuthenticationMethod.Read.All` |
| appcontrol | `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All` |
| backup | No Graph permissions (Veeam/Azure Backup have their own auth) |

### 2. Set environment variables

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

### 3. Verify and run

```bash
# Check auth
python3 shared/graph_auth.py --check

# Patch compliance report
python3 e8cr-vmpm/scripts/graph_patches.py --action compliance-report

# MFA coverage
python3 e8cr-identity/scripts/entra_mfa.py --action coverage

# Admin role audit
python3 e8cr-identity/scripts/entra_roles.py --action list
```

---

## Setup: autonomous agents (with OpenClaw)

This is where E8CR becomes hands-off. Each bot runs as an OpenClaw instance that continuously monitors your tenant, runs the right scripts at the right time, and generates reports on schedule.

### What is OpenClaw?

[OpenClaw](https://github.com/openclaw/openclaw) is an open-source AI assistant framework. You install it, connect it to an LLM (Anthropic Claude, OpenAI, etc.), and give it skills — directories containing a `SKILL.md` (instructions) and scripts (tools). The AI reads the instructions, uses the tools, and operates autonomously.

Each E8CR bot is an OpenClaw skill. The `SKILL.md` file tells OpenClaw:
- What the bot's job is
- What scripts are available and how to run them
- What environment variables it needs
- When to run checks (scheduling)
- What to do with the results

### Why one instance per bot?

Each bot gets its own OpenClaw instance because:
- **Isolation** — the Identity bot shouldn't be able to run VM+PM scripts (least privilege)
- **Independent scheduling** — each bot runs on its own cadence
- **Separate memory** — each bot maintains its own context and findings history
- **Failure isolation** — if one bot crashes, the others keep running

### Install OpenClaw

```bash
# Install OpenClaw
curl -fsSL https://openclaw.ai/install.sh | bash

# Or via npm
npm install -g openclaw@latest
```

Full install guide: [docs.openclaw.ai/start/getting-started](https://docs.openclaw.ai/start/getting-started)

### Set up each bot

For each bot, create a separate OpenClaw workspace:

```bash
# Example: VM+PM bot
mkdir -p ~/e8cr-vmpm
cd ~/e8cr-vmpm

# Initialise OpenClaw workspace
openclaw onboard --install-daemon

# Install the E8CR VM+PM skill
# Copy (or symlink) the bot directory into the OpenClaw skills folder:
cp -r /path/to/e8cr-squad/e8cr-vmpm ~/.openclaw/workspace/skills/
cp -r /path/to/e8cr-squad/shared ~/.openclaw/workspace/skills/e8cr-vmpm/

# Set your tenant credentials in the OpenClaw environment
# (add to ~/.openclaw/workspace/.env or your shell profile)
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

Repeat for each bot (`e8cr-identity`, `e8cr-appcontrol`, `e8cr-backup`).

### Running multiple instances on one machine

Each OpenClaw instance needs its own port. Set this during onboarding or in the config:

```bash
# Bot 1: VM+PM (default port)
openclaw gateway --port 18789

# Bot 2: Identity
openclaw gateway --port 18790

# Bot 3: Application Control
openclaw gateway --port 18791

# Bot 4: Backup
openclaw gateway --port 18792
```

Each instance runs as a separate system service (launchd on macOS, systemd on Linux).

> **Tip:** For production deployments, a single Mac Mini M4 (16GB) can comfortably run all 4 bots. See [hardware recommendations](#hardware).

---

## Safe mode

**All write actions are disabled by default.** Scripts that can modify your tenant (start scans, deploy policies, patch devices) require explicit opt-in:

```bash
export E8CR_ENABLE_CHANGES=true
```

Run in audit mode first. Review the output. Enable changes only when you're confident.

---

## Dependencies

Python 3.10+. Core scripts use standard library only (`urllib`, `json`, `argparse`). No pip install required.

Optional (for Greenbone vulnerability scanning):
```bash
pip install -r requirements.txt  # python-gvm, lxml
```

---

## Hardware

E8CR is designed to run on modest hardware. Recommended:

| Setup | Hardware | Notes |
|-------|----------|-------|
| **Starter** | Any Linux box or Mac with 8GB+ RAM | Run 1-2 bots |
| **Full squad** | Mac Mini M4 (16GB) or equivalent | All 4 bots comfortably |
| **Enterprise** | Dedicated server or VM per bot | Maximum isolation |

The bots themselves are lightweight — the LLM inference (via OpenClaw) is the main resource consumer. Using a cloud LLM (Anthropic, OpenAI) means your hardware only needs to run the scripts and store reports.

---

## Project structure

```
e8cr-squad/
├── run_all.py              # Unified assessment runner (demo + live)
├── shared/
│   └── graph_auth.py       # Microsoft Graph authentication (all bots share this)
├── e8cr-vmpm/
│   ├── SKILL.md            # OpenClaw skill definition
│   └── scripts/            # Python tools (graph_patches.py, greenbone_scan.py, etc.)
├── e8cr-identity/
│   ├── SKILL.md
│   └── scripts/            # (entra_mfa.py, entra_roles.py, entra_ca.py, etc.)
├── e8cr-appcontrol/
│   ├── SKILL.md
│   └── scripts/            # (intune_appcontrol.py, intune_macros.py, etc.)
├── e8cr-backup/
│   ├── SKILL.md
│   └── scripts/            # (backup_jobs.py, restore_test.py, etc.)
├── requirements.txt        # Optional deps (Greenbone only)
├── CONTRIBUTING.md
└── LICENSE                 # Apache 2.0
```

---

## What this is NOT

- Not a turnkey "click and you're compliant" solution
- Not a substitute for a qualified IRAP assessor
- Not responsible for your tenant configuration — you own that
- Not a SaaS product — it runs on your hardware, you operate it

This is a reference implementation. It's working, runnable automation built by someone who got tired of watching organisations struggle with ML2 compliance. Use it, fork it, adapt it.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). PRs welcome — especially tests, backup provider adapters, and report improvements.

## License

[Apache License 2.0](./LICENSE)

---

Built by [Richard Dobson](https://dobsondevelopment.com.au) · [OpenClaw](https://github.com/openclaw/openclaw)
