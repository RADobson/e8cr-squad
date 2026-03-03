# HEARTBEAT.md — Backup Bot

## Every Cycle (Critical)
- If any restore test failure is detected → P1 escalation
- If any critical asset has no backup coverage → P1 escalation

## Daily
```bash
python3 scripts/provider_dispatch.py --mode fetch-jobs
python3 scripts/backup_jobs.py --mode audit --provider all
```
- Update MEMORY.md with job success/failure counts

## Weekly
```bash
python3 scripts/coverage_audit.py --assets ./evidence/assets.json --protected ./evidence/protected.json
python3 scripts/restore_test.py --mode simulate --target "sample"
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/backup-report.html
```

## Monthly
```bash
python3 scripts/access_control_audit.py
```
- Review exceptions + drift

## After each run
Update MEMORY.md:
- timestamps
- failures
- coverage gaps
- restore tests performed
