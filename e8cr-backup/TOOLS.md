# TOOLS.md — Backup Bot Script Reference

## Provider detection & auth

```bash
python3 scripts/provider_dispatch.py --mode detect
python3 scripts/auth_scaffold.py
```

## Job monitoring

```bash
python3 scripts/provider_dispatch.py --mode fetch-jobs
python3 scripts/backup_jobs.py --mode summary --provider all
python3 scripts/backup_jobs.py --mode audit --provider veeam
```

Interpretation:
- Failures on critical jobs = P1
- Intermittent failures = trend analysis (often credential expiry)
- Success without recent restore tests = still risky

## Coverage audit

```bash
python3 scripts/coverage_audit.py --assets assets.json --protected protected.json
```

Interpretation:
- Any critical asset not protected = P1
- Coverage gaps should include owner + remediation plan

## Restore testing

```bash
python3 scripts/restore_test.py --mode simulate --target "Finance Share"
```

Interpretation:
- A restore test must prove both:
  - the restore completes
  - the restored data is usable (integrity check)

Never perform real restores without approval.

## ML2 checks

```bash
python3 scripts/ml2_checks.py --input ./evidence/
```

## Access control audit

```bash
python3 scripts/access_control_audit.py
```

Interpretation:
- Backup credentials should be least-privilege
- Admin credentials should be protected with MFA where possible

## Reports & demos

```bash
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/backup-report.html
python3 scripts/demo_generate.py --output ./demo --full-pipeline
```
