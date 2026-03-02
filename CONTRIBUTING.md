# Contributing to E8CR Squad

Thanks for your interest. Contributions are welcome — bugs, improvements, new features, and documentation fixes.

## Ground rules

- **Scope discipline** — Only touch what you're changing. Don't refactor adjacent code as a side effect.
- **No secrets** — Never commit credentials, tokens, or real tenant data. Use env vars only.
- **Safe by default** — Any new script that can make changes must respect `E8CR_ENABLE_CHANGES`. Read-only/audit actions never need this flag.
- **Test with demo mode first** — All scripts should work with `--demo` or synthetic data before touching a real tenant.

## How to contribute

1. Fork the repo
2. Create a branch: `git checkout -b fix/my-thing`
3. Make changes, test locally with demo data
4. Open a PR with a clear description of what changed and why

## Running demo mode locally

```bash
# Generate all demo data and reports
python3 e8cr-vmpm/scripts/demo_generate.py --output demo/vmpm --full-pipeline
python3 e8cr-identity/scripts/demo_generate.py --output demo/identity
python3 e8cr-identity/scripts/generate_report.py --input demo/identity --output demo/identity/identity-report.html
python3 e8cr-appcontrol/scripts/demo_generate.py --output demo/appcontrol --full-pipeline
python3 e8cr-backup/scripts/demo_generate.py --output demo/backup --full-pipeline
python3 e8cr-edr/scripts/demo_generate.py --output demo/edr --full-pipeline
```

## What needs the most help

- Tests (even basic smoke tests that run demo pipelines)
- Additional backup provider adapters (currently: Veeam + Azure Backup)
- MDVM → Greenbone result normalisation improvements
- Better inactive admin detection (signInActivity requires beta API)
- GitHub Actions CI

## Questions

Open an issue. Happy to discuss.
