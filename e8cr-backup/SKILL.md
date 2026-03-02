---
name: e8cr-backup
description: Essential Eight Backup Bot — autonomous backup monitoring, coverage auditing, restore testing, and ML2 evidence generation.
---

# E8CR Backup Bot

Autonomous backup operations agent for Essential Eight **Regular Backups (ML2)**.

## What it covers
1. Backup job monitoring (success/fail/missed)
2. Coverage gap detection (assets not protected)
3. Restore test execution + integrity verification
4. Evidence generation for auditors

## Scripts

### Provider authentication + dispatch
```bash
# Check configured providers (Veeam, Azure Backup)
python3 scripts/auth_scaffold.py
python3 scripts/provider_dispatch.py --mode detect

# Fetch jobs from configured provider (auto-detects or --force-provider)
python3 scripts/provider_dispatch.py --mode fetch-jobs
python3 scripts/provider_dispatch.py --mode fetch-jobs --force-provider veeam

# Fetch jobs directly from specific adapter
python3 scripts/backup_jobs.py --mode summary --provider all
python3 scripts/backup_jobs.py --mode audit --provider veeam
```

### Adapters (Veeam + Azure Backup)
```bash
# Built-in sample mode (for demos)
# Veeam API adapter stub: scripts/adapters.py:veeam_fetch_jobs_sample()
# Azure API adapter stub: scripts/adapters.py:azure_fetch_jobs_sample()
# Normalized schema: scripts/adapters.py:normalize_jobs()
```

### Coverage audit
```bash
python3 scripts/coverage_audit.py --assets /path/assets.json --protected /path/protected.json
```

### Restore test workflow
```bash
python3 scripts/restore_test.py --mode simulate --target "Finance Share"
```

### ML2 compliance checks
```bash
python3 scripts/ml2_checks.py --input /tmp/e8cr-demo/backup
```

### Backup IAM access control audit
```bash
python3 scripts/access_control_audit.py
python3 scripts/access_control_audit.py --input /path/custom-iam.json
```

### Evidence report
```bash
python3 scripts/generate_report.py --input /tmp/e8cr-demo/backup --output backup-report.html
python3 scripts/generate_report.py --input /tmp/e8cr-demo/backup --output backup-report.html --type executive
```

### Full demo data pipeline
```bash
python3 scripts/demo_generate.py --output /tmp/e8cr-demo/backup
python3 scripts/demo_generate.py --output /tmp/e8cr-demo/backup --full-pipeline
```

## Safe Mode

Write actions are **disabled by default**. To enable:
```bash
export E8CR_ENABLE_CHANGES=true
```
Run in audit mode first. Review outputs. Then enable changes intentionally.

## Operational cadence
- Continuous: monitor failed/missed jobs
- Daily: backup success summary
- Weekly: coverage + retention checks
- Monthly: restore test + evidence pack

## ML2 checks
- Backups of important data/software/configuration are performed and retained
- Restores are tested and evidence recorded
- Access to backups restricted from non-backup privileged accounts
