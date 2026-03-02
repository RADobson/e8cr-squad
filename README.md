# E8CR Squad

[![CI](https://github.com/RADobson/e8cr-squad/actions/workflows/ci.yml/badge.svg)](https://github.com/RADobson/e8cr-squad/actions/workflows/ci.yml)

Autonomous Essential Eight compliance bots. Open-source reference implementation built on [OpenClaw](https://github.com/openclaw/openclaw).

## What this is

A set of OpenClaw skills (autonomous AI agents) that continuously audit and report on Australian Government Essential Eight Maturity Level 2 compliance. Each bot connects to your Microsoft 365 tenant via Graph API, runs on your hardware, and generates evidence-ready reports.

**Reference implementation** — this is working, runnable automation. It is not a turnkey compliance solution. You are responsible for how you run it.

## The bots

| Bot | Controls covered (ML2) | Primary integrations | Key scripts |
|-----|------------------------|---------------------|-------------|
| **e8cr-vmpm** | Patch Applications, Patch OS | Intune (Graph API), Greenbone/OpenVAS, MDVM, CISA KEV, EPSS | `graph_patches.py`, `graph_mdvm.py`, `greenbone_scan.py`, `vuln_prioritise.py` |
| **e8cr-identity** | Multi-factor Authentication, Restrict Admin Privileges | Microsoft Entra ID (Graph API) | `entra_mfa.py`, `entra_roles.py`, `entra_ca.py`, `entra_signin.py` |
| **e8cr-appcontrol** | Application Control, Configure Office Macros, User Application Hardening | Intune (Graph API) | `intune_appcontrol.py`, `intune_macros.py`, `intune_hardening.py` |
| **e8cr-backup** | Regular Backups | Veeam B&R, Azure Backup | `backup_jobs.py`, `coverage_audit.py`, `restore_test.py`, `ml2_checks.py` |
| **e8cr-edr** | (SOC capability — not an E8 control, but complements the suite) | Microsoft Defender for Endpoint | `defender_alerts.py`, `triage.py`, `threat_intel.py`, `response_engine.py` |

## Architecture

```
┌───────────────────────────────────────────────────┐
│  Your on-prem hardware (Mac Mini or any Linux box) │
│                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ...   │
│  │ vmpm bot │  │identity  │  │appcontrol│         │
│  │(OpenClaw)│  │  bot     │  │   bot    │         │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘         │
│       │              │              │               │
│       └──────────────┴──────────────┘               │
│                      │                              │
│              shared/graph_auth.py                   │
│         (client credentials → Graph token)          │
└───────────────────────────────────────────────────┘
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
Microsoft Graph API          Greenbone/OpenVAS
(Intune, Entra ID,           (optional, E3 tenants)
 Defender, Sentinel)
```

- **On-prem by default** — your security data never leaves your network
- **Shared auth** — all bots use `shared/graph_auth.py` (client credentials flow, no user login required)
- **Audit-only by default** — write actions require `E8CR_ENABLE_CHANGES=true`
- **Each bot is independent** — run one, some, or all. No inter-bot dependencies.

## Safe Mode (audit-only by default)

**Write actions are disabled by default.** Any action that can modify your tenant (isolate endpoints, block IOCs, start vulnerability scans, etc.) requires explicit opt-in:

```bash
export E8CR_ENABLE_CHANGES=true
```

Run in audit mode first. Review the output. Then enable changes if you're confident.

## Quick Start — One command, full assessment

```bash
# Run all 5 bots with synthetic data — no tenant needed
python3 run_all.py --demo --output ./my-assessment

# Open the unified compliance dashboard
open ./my-assessment/e8cr-assessment.html
```

This generates a complete Essential Eight ML2 compliance report with:
- Unified dashboard with compliance score ring, priority issues, and E8 control matrix
- Individual bot reports with detailed findings
- All evidence files (JSON) for audit purposes

Options:
```bash
# Custom company name
python3 run_all.py --demo --company "Acme Corp" --output ./report

# Run specific bots only
python3 run_all.py --demo --bots vmpm identity backup --output ./partial

# Live mode (real M365 tenant — see below)
python3 run_all.py --output ./live-assessment
```

### Pre-generated demos

The `demo/` folder contains pre-generated reports you can open right now — including `demo/unified/e8cr-assessment.html` (the combined dashboard).

To regenerate individual bots:

```bash
# VM+PM Bot
python3 e8cr-vmpm/scripts/demo_generate.py --output demo/vmpm --full-pipeline

# Identity Bot
python3 e8cr-identity/scripts/demo_generate.py --output demo/identity --full-pipeline

# Application Control Bot
python3 e8cr-appcontrol/scripts/demo_generate.py --output demo/appcontrol --full-pipeline

# Backup Bot
python3 e8cr-backup/scripts/demo_generate.py --output demo/backup --full-pipeline

# EDR Bot
python3 e8cr-edr/scripts/demo_generate.py --output demo/edr --full-pipeline
```

Open the HTML reports:
- `demo/vmpm/weekly-report.html`
- `demo/identity/identity-report.html`
- `demo/appcontrol/appcontrol-report.html`
- `demo/backup/backup-report.html`
- `demo/edr/edr-report.html`

## Live mode — Real M365 tenant

### 1. Create an App Registration in Entra ID

Go to Azure Portal → Entra ID → App registrations → New registration.

Grant the following **Application** (not Delegated) permissions and grant admin consent:

| Bot | Required permissions |
|-----|---------------------|
| vmpm | `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `Vulnerability.Read.All`, `Software.Read.All` |
| identity | `User.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.All`, `UserAuthenticationMethod.Read.All` |
| appcontrol | `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All` |
| backup | No Graph permissions needed (Veeam/Azure Backup use their own auth) |
| edr | `SecurityAlert.Read.All`, `SecurityIncident.ReadWrite.All`, `Machine.Read.All` |

### 2. Set environment variables

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"

# Greenbone (vmpm only, if not using MDVM)
export GREENBONE_HOST="127.0.0.1"
export GREENBONE_PASSWORD="your-greenbone-password"
```

### 3. Verify authentication

```bash
python3 shared/graph_auth.py --check
# OK: Authenticated to tenant 'Meridian Civil Group' (abc-123...)
```

### 4. Run a bot

```bash
# Patch compliance report
python3 e8cr-vmpm/scripts/graph_patches.py --action compliance-report

# MFA coverage
python3 e8cr-identity/scripts/entra_mfa.py --action coverage

# Admin role audit
python3 e8cr-identity/scripts/entra_roles.py --action list
```

## Dependencies

Core bots use Python standard library only (`urllib`, `json`, `argparse`). No pip install required unless using Greenbone:

```bash
pip install -r requirements.txt   # only needed for Greenbone/OpenVAS scanner
```

Python 3.10+.

## What this is NOT

- Not a turnkey compliance solution
- Not "click once and you're ML2"
- Not a substitute for a qualified assessor
- Not responsible for your tenant configuration — you own that

## Security & responsibility

These tools connect to sensitive APIs and produce sensitive outputs (vulnerability lists, admin accounts, backup gaps). Treat outputs as confidential. Default to read-only mode. Review before enabling write actions.

## License

Apache License 2.0 — see [LICENSE](./LICENSE).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).
