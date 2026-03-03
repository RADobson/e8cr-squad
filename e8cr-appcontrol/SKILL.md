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

## Contract source of truth
- `bot.contract.yaml` is authoritative for controls, required files, command registry, and evidence outputs.
- Keep `SKILL.md` and `HEARTBEAT.md` aligned with the contract.

## Common operations

### Daily cycle orchestration (preferred)
```bash
python3 scripts/run_cycle.py --period daily
```

### Weekly cycle orchestration (preferred)
```bash
python3 scripts/run_cycle.py --period weekly
```

### Audit current posture (manual)
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

### Drift detection + state update
```bash
python3 scripts/drift_detect.py --current-dir ./evidence/<date> --state-file ./state/last_snapshot.json --output ./evidence/<date>/drift.json
```

### Report generation
```bash
python3 scripts/generate_report.py --input ./evidence/<date> --output ./evidence/<date>/appcontrol-report.html
```

### Evidence schema validation
```bash
python3 scripts/validate_evidence.py --evidence-dir ./evidence/<date> --schemas-dir ./schemas
```

### Memory update from evidence deltas
```bash
python3 scripts/update_memory.py --memory ./MEMORY.md --drift ./evidence/<date>/drift.json --evidence-dir ./evidence/<date>
```

### Demo mode
```bash
python3 scripts/demo_generate.py --output ./demo --full-pipeline
```

## Operating rules
- Audit-first (collect telemetry before enforcement)
- Exceptions must be documented and scoped
- This bot is currently **audit-only**; write/deploy actions are intentionally not implemented in this package.
- Enabling `E8CR_ENABLE_CHANGES=true` does not enable deployment by itself; it is reserved for future controlled write scripts.
