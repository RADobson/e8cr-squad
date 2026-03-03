# TOOLS.md — Application Control Bot Script Reference

## Authentication
Uses Graph app-only auth via shared token helper.

Required:
```bash
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
```

## Scripts

### intune_appcontrol.py — WDAC/AppLocker posture
```bash
python3 scripts/intune_appcontrol.py --mode audit
python3 scripts/intune_appcontrol.py --mode compliance
python3 scripts/intune_appcontrol.py --mode events
```

Interpretation:
- Audit mode present but no enforcement: good starting state
- Enforcement without a documented rollout: operational risk
- Frequent blocks of signed Microsoft binaries: policy too strict or mis-scoped

### intune_macros.py — Office macro restrictions
```bash
python3 scripts/intune_macros.py --mode audit
python3 scripts/intune_macros.py --mode compliance
```

Interpretation:
- Internet-sourced macros should be blocked by default
- Exceptions should be rare, scoped, and time-bound

### intune_hardening.py — User application hardening
```bash
python3 scripts/intune_hardening.py --mode audit
python3 scripts/intune_hardening.py --mode compliance
```

Interpretation:
- Harden browsers (SmartScreen, extension controls, etc.)
- Harden Office and PDF readers to reduce exploitability

### generate_report.py — Evidence report
```bash
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/appcontrol-report.html
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/appcontrol-report.html --type executive
```

### demo_generate.py — Synthetic demo
```bash
python3 scripts/demo_generate.py --output ./demo --full-pipeline
```

## Orchestration + state
Primary operating entrypoint:
```bash
python3 scripts/run_cycle.py --period daily
python3 scripts/run_cycle.py --period weekly
```

State + drift:
- `state/last_snapshot.json` stores the last baseline snapshot
- `scripts/drift_detect.py` compares current evidence with previous snapshot

Evidence schema validation:
```bash
python3 scripts/validate_evidence.py --evidence-dir ./evidence/YYYY-MM-DD --schemas-dir ./schemas
```

## Safe Mode
This package is currently audit-only; no deploy/rollback scripts are implemented yet.
`E8CR_ENABLE_CHANGES` is reserved for future controlled write capabilities.
