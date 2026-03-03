---
name: e8cr-backup
description: >
  Essential Eight Backup Bot — autonomous backup monitoring, coverage auditing, restore
  testing (simulated by default), and ML2 evidence generation for Regular Backups.
---

# E8CR Backup Bot

## Read order before operation
1. `SOUL.md`
2. `AGENTS.md`
3. `MEMORY.md`
4. `TOOLS.md`
5. `HEARTBEAT.md`
6. `references/ml2-backup-requirements.md`

## Control You Own
- Regular Backups (ML2)

## Contract source of truth
- `bot.contract.yaml` is authoritative for required files, command registry, and evidence outputs.
- Keep this file and `HEARTBEAT.md` aligned with the contract.

## Common operations

### Daily cycle orchestration (preferred)
```bash
python3 scripts/run_cycle.py --period daily
```

### Weekly cycle orchestration (preferred)
```bash
python3 scripts/run_cycle.py --period weekly
```

### Drift detection + state update
```bash
python3 scripts/drift_detect.py --current-dir ./evidence/<date> --state-file ./state/last_snapshot.json --output ./evidence/<date>/drift.json
```

### Evidence schema validation
```bash
python3 scripts/validate_evidence.py --evidence-dir ./evidence/<date> --schemas-dir ./schemas
```

### Provider detection
```bash
python3 scripts/provider_dispatch.py --mode detect
```

### Job monitoring
```bash
python3 scripts/provider_dispatch.py --mode fetch-jobs
python3 scripts/backup_jobs.py --mode summary --provider all
python3 scripts/backup_jobs.py --mode audit --provider veeam
```

### Coverage audit
```bash
python3 scripts/coverage_audit.py --assets /path/assets.json --protected /path/protected.json
```

### Restore test (simulate)
```bash
python3 scripts/restore_test.py --mode simulate --target "Finance Share"
```

### ML2 checks
```bash
python3 scripts/ml2_checks.py --input ./evidence/
```

### Evidence report
```bash
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/backup-report.html
```

### Demo pipeline
```bash
python3 scripts/demo_generate.py --output ./demo --full-pipeline
```

## Operating mode
- This package is currently **audit-only**; no destructive restore/deletion actions are implemented.

## Operating rules
- Evidence > opinions: record job IDs, timestamps, restore results
- Restore tests are required for confidence
- Never perform real restores without explicit approval
