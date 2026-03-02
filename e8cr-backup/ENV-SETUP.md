# E8CR Backup Bot — Environment Setup

## Quick Start (Demo Mode)

```bash
python3 scripts/demo_generate.py --output /tmp/e8cr-demo/backup --full-pipeline
# Opens: /tmp/e8cr-demo/backup/backup-report.html
```

## Real Tenant Configuration

### Option 1: Veeam Backup & Replication

```bash
export VEEAM_BASE_URL="https://veeam-server:9398"
export VEEAM_USERNAME="backup-admin@domain.com"
export VEEAM_PASSWORD="<secure-password>"
export VEEAM_VERIFY_SSL="true"

# Verify connection
python3 scripts/provider_dispatch.py --mode detect
python3 scripts/provider_dispatch.py --mode fetch-jobs
```

**Prerequisites:**
- Veeam Backup & Replication server (v12+)
- API user with REST API access
- Network connectivity to Veeam server + management port (9398)

### Option 2: Azure Backup (Azure Recovery Services Vault)

```bash
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
export AZURE_VAULT_NAME="<vault-name>"
export AZURE_RESOURCE_GROUP="<resource-group>"
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_ID="<app-registration-client-id>"
export AZURE_CLIENT_SECRET="<app-registration-client-secret>"

# Verify connection
python3 scripts/provider_dispatch.py --mode detect
python3 scripts/provider_dispatch.py --mode fetch-jobs
```

**Prerequisites:**
- Azure subscription with Recovery Services Vault
- Azure AD app registration (Service Principal) with:
  - `Backup Operator` or `Backup Reader` role on vault
  - `Backup Contributor` if managing policies
- Credentials stored securely (use .env or secrets management)

### Option 3: Hybrid (Auto-Detect)

If both providers are configured, provider_dispatch will use Veeam first, then fall back to Azure.

Override with:
```bash
python3 scripts/provider_dispatch.py --mode fetch-jobs --force-provider azure
```

## Real Tenant Data Sources

### For backup-jobs.json
- Veeam: REST API `/api/backupServers` + `/api/jobs`
- Azure: ARM API `/subscriptions/{}/resourceGroups/{}/providers/Microsoft.RecoveryServices/vaults/{}/backupJobs`

### For coverage-audit.json
- Asset inventory: CMDB, Intune device inventory, or on-premises discovery tool
- Protected assets: Compare against backup job scopes (Veeam repo volumes, Azure backup policies)

### For restore-test.json
- Schedule monthly restore drills
- Capture: backup source, restore destination, integrity verification (checksums)
- Alert if restore fails or verifies fail

### For access-control.json
- Veeam: Check `Backup Admin` roles via Veeam console
- Azure: Query Azure RBAC roles on Recovery Services Vault via ARM API

## Operational Integration

### Daily
```bash
python3 scripts/provider_dispatch.py --mode fetch-jobs > /tmp/daily-jobs.json
python3 scripts/ml2_checks.py --input /tmp > /tmp/daily-checks.json
# Alert if any jobs failed or checks are "fail"
```

### Weekly
```bash
python3 scripts/coverage_audit.py --assets /path/assets.json --protected /path/protected.json
# Identify new uncovered assets
```

### Monthly
```bash
# Trigger restore test (manual or automated)
python3 scripts/restore_test.py --mode simulate --target "Backup-Share"
python3 scripts/access_control_audit.py > /tmp/access-control.json
# Run full evidence generation
python3 scripts/generate_report.py --input /tmp --output backup-evidence-2026-03.html
```

## Troubleshooting

### "No backup providers configured"
- Check environment variables are exported (not just in .env)
- Verify provider credentials are correct
- Test connectivity to backup platform API endpoint

### "Job success rate is low"
- Check Veeam/Azure logs for job failures
- Verify storage repository/vault capacity
- Check network connectivity between backup server and clients

### "Coverage gaps detected"
- Add missing assets to backup policy
- Update asset inventory source
- Run coverage_audit again after changes

## Security Notes

- Store credentials in:
  - `.env` file (git-ignored)
  - Environment variable management (Vault, Secrets Manager)
  - 1Password or similar (via `op` CLI)
- Rotate API credentials regularly (every 90 days)
- Restrict access to backup platform credentials (backup admins only)
- Enable MFA on backup admin accounts
- Audit API access logs weekly
