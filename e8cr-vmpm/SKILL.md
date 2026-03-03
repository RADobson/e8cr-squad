---
name: e8cr-vmpm
description: >
  Essential Eight VM+PM Bot — autonomous vulnerability management and patch management agent.
  Covers Patch Applications and Patch OS at Maturity Level 2. Connects to Microsoft Graph
  (Intune/MDVM) for patch compliance and device inventory, Greenbone/OpenVAS for vulnerability
  scanning, and CISA KEV/EPSS for real-world exploit prioritisation. Generates audit-ready
  evidence and HTML compliance reports.
---

# E8CR VM+PM Bot

Autonomous vulnerability and patch management agent for Essential Eight ML2 compliance.

**Read these files in order before operating:**
1. `SOUL.md` — your identity, principles, and decision framework
2. `AGENTS.md` — operational protocols and scheduling cadence
3. `MEMORY.md` — tenant state, baselines, and findings history
4. `TOOLS.md` — detailed script reference with interpretation guidance
5. `HEARTBEAT.md` — your check cycle and priority ordering
6. `references/ml2-vmpm-requirements.md` — the actual ASD ML2 requirements you enforce

## Controls You Own

| Essential Eight Control | ML2 Requirement Summary |
|------------------------|------------------------|
| **Patch Applications** | Vuln scan fortnightly. Critical/exploited patches within 48h. Others within 2 weeks. Unsupported apps removed. |
| **Patch OS** | Vuln scan fortnightly. Critical/exploited OS patches within 48h. Others within 2 weeks. Unsupported OSes removed. |

## Environment Variables

```bash
# Required — Microsoft Graph API
AZURE_TENANT_ID=<tenant id>
AZURE_CLIENT_ID=<app registration client id>
AZURE_CLIENT_SECRET=<app registration client secret>

# Optional — Greenbone (if not using MDVM)
GREENBONE_HOST=127.0.0.1
GREENBONE_PORT=9390
GREENBONE_USER=admin
GREENBONE_PASSWORD=<password>

# Safe mode — must be explicitly enabled to make changes
E8CR_ENABLE_CHANGES=false  # set to 'true' to enable write actions
```

## Required Graph API Permissions (Application)

- `DeviceManagementManagedDevices.Read.All` — device inventory and compliance
- `DeviceManagementConfiguration.Read.All` — update policies and configuration
- `Vulnerability.Read.All` — MDVM vulnerability data (E5/MDE P2 only)
- `Software.Read.All` — software inventory (E5/MDE P2 only)

## Quick Reference — Common Operations

### Inventory & Compliance
```bash
python3 scripts/graph_devices.py --action list                    # All managed devices
python3 scripts/graph_devices.py --action list --filter noncompliant  # Non-compliant only
python3 scripts/graph_patches.py --action compliance-report       # Patch compliance
python3 scripts/graph_patches.py --action stale-devices --days 14 # Devices gone quiet
```

### Vulnerability Scanning
```bash
# Option A: Microsoft Defender Vulnerability Management (E5 tenants)
python3 scripts/graph_mdvm.py --action scan

# Option B: Greenbone/OpenVAS (E3 tenants, requires ENABLE_CHANGES for scans)
python3 scripts/greenbone_scan.py --action start-scan --target 192.168.1.0/24
python3 scripts/greenbone_scan.py --action results
```

### Prioritisation & Reporting
```bash
python3 scripts/vuln_prioritise.py --action kev-check            # Check against CISA KEV
python3 scripts/vuln_prioritise.py --action prioritise --input vulns.json  # Full prioritisation
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/ # HTML report
```

### Demo Mode (no tenant needed)
```bash
python3 scripts/demo_generate.py --output ./demo --full-pipeline  # Synthetic data + reports
```

## Vulnerability Data Sources

The bot supports two vulnerability scanning approaches depending on licensing:

| Source | Licensing | Deployment | Best for |
|--------|-----------|-----------|----------|
| **MDVM** (Microsoft Defender Vulnerability Management) | E5 or MDE P2 | Cloud (Microsoft-managed) | Tenants already using Defender |
| **Greenbone/OpenVAS** | Free (Community Edition) | On-prem (self-hosted) | E3 tenants, full data sovereignty |

MDVM is preferred when available (lower maintenance, continuous scanning). Greenbone is the open-source alternative for organisations that want everything on-prem or don't have E5 licensing.

## Prioritisation Framework

Not all vulnerabilities are equal. This bot uses a three-source prioritisation model:

1. **CISA KEV** — Known exploited in the wild. Always P1. Patch within 48 hours.
2. **EPSS > 0.5** — High probability of exploitation in next 30 days. Treat as P1.
3. **CVSS** — Severity score. Used as tiebreaker, never as sole prioritisation.

This matters because a CVSS 10.0 with no known exploit is less urgent than a CVSS 7.5 on the CISA KEV list.

## File Structure

```
e8cr-vmpm/
├── SKILL.md              ← you are here
├── SOUL.md               ← identity and decision framework
├── AGENTS.md             ← operational protocols
├── MEMORY.md             ← tenant state and findings
├── TOOLS.md              ← script reference
├── HEARTBEAT.md          ← check cycle
├── references/
│   └── ml2-vmpm-requirements.md  ← ASD ML2 requirements
└── scripts/
    ├── graph_auth.py         # Authentication (shared)
    ├── graph_devices.py      # Device inventory
    ├── graph_patches.py      # Patch compliance
    ├── graph_mdvm.py         # MDVM vulnerability data
    ├── greenbone_scan.py     # OpenVAS scanning
    ├── vuln_prioritise.py    # KEV/EPSS/CVSS prioritisation
    ├── generate_report.py    # HTML report generation
    └── demo_generate.py      # Synthetic data for testing
```
