---
name: e8cr-appcontrol
description: Essential Eight Application Control Bot — autonomous policy engineer for WDAC/AppLocker, Office macro restrictions, and user application hardening. Connects to Microsoft Graph (Intune) for policy deployment and compliance monitoring. Use when operating as the Application Control bot, managing WDAC policies, auditing macro settings, enforcing browser/Office hardening, or generating ML2 evidence reports.
---

# E8CR Application Control Bot

Autonomous policy engineer covering three Essential Eight controls at ML2:
1. **Application Control** — WDAC/AppLocker policy management
2. **Configure MS Office Macro Settings** — Macro restriction enforcement
3. **User Application Hardening** — Browser, PDF reader, Office hardening

## Setup

Required environment variables:
```
AZURE_TENANT_ID=<customer tenant id>
AZURE_CLIENT_ID=<app registration client id>
AZURE_CLIENT_SECRET=<app registration client secret>
```

## Microsoft Graph Integration

### Authentication
Uses shared `graph_auth.py` (same as VM+PM and Identity bots). Client credentials flow.

Required Azure AD App Registration permissions (Application type):
- `DeviceManagementConfiguration.Read.All` — Read Intune configuration profiles
- `DeviceManagementConfiguration.ReadWrite.All` — Deploy/update configuration profiles
- `DeviceManagementManagedDevices.Read.All` — Read device compliance status

### Application Control Audit
`scripts/intune_appcontrol.py` — Pull WDAC/AppLocker policy status from Intune.
```bash
python3 scripts/intune_appcontrol.py --mode audit     # Current policy status
python3 scripts/intune_appcontrol.py --mode events     # Blocked execution events
python3 scripts/intune_appcontrol.py --mode compliance  # Per-device compliance
```

### Macro Settings Audit
`scripts/intune_macros.py` — Audit Office macro configuration profiles.
```bash
python3 scripts/intune_macros.py --mode audit          # Current macro policies
python3 scripts/intune_macros.py --mode compliance      # Per-device macro compliance
```

### User Application Hardening Audit
`scripts/intune_hardening.py` — Audit browser, PDF, Office hardening profiles.
```bash
python3 scripts/intune_hardening.py --mode audit       # Current hardening policies
python3 scripts/intune_hardening.py --mode compliance   # Per-device compliance
```

### Evidence Report
`scripts/generate_report.py` — Generate ML2 compliance evidence report.
```bash
python3 scripts/generate_report.py --input /tmp/e8cr-demo/appcontrol/ --output report.html
python3 scripts/generate_report.py --input /tmp/e8cr-demo/appcontrol/ --output report.html --type executive
```

### Demo Data
`scripts/demo_generate.py` — Generate realistic synthetic data for sales demos.
```bash
python3 scripts/demo_generate.py --output /tmp/e8cr-demo/appcontrol/
python3 scripts/demo_generate.py --output /tmp/e8cr-demo/appcontrol/ --full-pipeline
```

## Safe Mode

Write actions are **disabled by default**. To enable:
```bash
export E8CR_ENABLE_CHANGES=true
```
Run in audit mode first. Review outputs. Then enable changes intentionally.

## Operational Cadence

- **Continuous:** Monitor WDAC block events, exception requests
- **Daily:** Review blocked executions, check for software needing policy updates
- **Weekly:** Policy compliance report, exception review
- **Monthly:** Full policy audit, stale exception cleanup, ML2 evidence snapshot

## ML2 Requirements Covered

### Application Control (ML2)
- Application control implemented on workstations
- Restricts execution to approved set (publisher rules + path rules + hash rules)
- Microsoft's recommended block rules implemented
- Rulesets validated annually or more frequently

### Configure MS Office Macro Settings (ML2)
- Macros from internet are blocked (Mark of the Web)
- Macros only allowed in trusted locations with trusted publishers
- Win32 API access from macros is blocked

### User Application Hardening (ML2)
- Web browsers don't process Java from internet
- Web browsers don't process web advertisements
- IE11 disabled or removed
- .NET Framework 3.5 disabled or removed (if not needed)
- PowerShell 2.0 disabled or removed
