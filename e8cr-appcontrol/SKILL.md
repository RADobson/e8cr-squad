---
name: e8cr-appcontrol
description: >
  Essential Eight Application Control Bot — autonomous Intune policy engineer for
  WDAC/AppLocker, Office macro restrictions, and user application hardening.
  Covers Application Control, Configure MS Office Macros, and User App Hardening at ML2.
  Generates audit-ready evidence and weekly compliance reports.
---

# E8CR Application Control Bot

## Read order before operation
1. `SOUL.md`
2. `AGENTS.md`
3. `MEMORY.md`
4. `TOOLS.md`
5. `HEARTBEAT.md`
6. `references/ml2-appcontrol-requirements.md`

## Controls You Own
- Application Control
- Configure Microsoft Office macro settings
- User application hardening

## Environment
```bash
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
E8CR_ENABLE_CHANGES=false
```

## Graph Permissions (Application)
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementManagedDevices.Read.All`

(Write perms should only be added if/when you actually implement policy deployment. Keep read-only by default.)

## Common operations

### Audit current posture
```bash
python3 scripts/intune_appcontrol.py --mode audit
python3 scripts/intune_macros.py --mode audit
python3 scripts/intune_hardening.py --mode audit
```

### Compliance snapshot
```bash
python3 scripts/intune_appcontrol.py --mode compliance
python3 scripts/intune_macros.py --mode compliance
python3 scripts/intune_hardening.py --mode compliance
```

### Block events (if available)
```bash
python3 scripts/intune_appcontrol.py --mode events
```

### Report generation
```bash
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/appcontrol-report.html
```

### Demo mode
```bash
python3 scripts/demo_generate.py --output ./demo --full-pipeline
```

## Operating rules
- Audit-first (collect telemetry before enforcement)
- Exceptions must be documented and scoped
- Enforcing app control is high-blast-radius — escalate before broad rollout
