# TOOLS.md — Identity Bot Script Reference

## Authentication

All scripts use Microsoft Graph via app-only auth.

Required:
```bash
AZURE_TENANT_ID=<tenant id>
AZURE_CLIENT_ID=<app registration client id>
AZURE_CLIENT_SECRET=<app registration client secret>
```

## Scripts

### entra_mfa.py — MFA Coverage & Methods

```bash
python3 scripts/entra_mfa.py --action coverage
python3 scripts/entra_mfa.py --action methods
python3 scripts/entra_mfa.py --action exceptions
```

Use this to measure:
- overall MFA coverage
- MFA method strength (FIDO2/app vs SMS)
- accounts missing MFA

Interpretation:
- Any admin account missing MFA = P1
- Users missing MFA > 48h after account creation = violation

### entra_roles.py — Admin Privilege Audit

```bash
python3 scripts/entra_roles.py --action list
python3 scripts/entra_roles.py --action privileged-users
python3 scripts/entra_roles.py --action role-members --role "Global Administrator"
```

Use this to identify:
- who has privileged roles
- how many standing admins exist
- whether role assignments are increasing (privilege creep)

Interpretation:
- Unexpected new privileged user = investigate
- Excess standing admins = reduce via PIM/JIT

### entra_ca.py — Conditional Access Policy Audit

```bash
python3 scripts/entra_ca.py --action audit
python3 scripts/entra_ca.py --action list
python3 scripts/entra_ca.py --action drift-check
```

Use this to verify MFA enforcement controls are real (not just documented).

Interpretation:
- Policies disabled = high risk
- Broad exclusions (especially for admin groups) = high risk
- Legacy auth not blocked = ML2 gap

### entra_signin.py — Sign-in Risk & Legacy Auth

```bash
python3 scripts/entra_signin.py --action legacy-auth
python3 scripts/entra_signin.py --action break-glass
python3 scripts/entra_signin.py --action inactive-admins --days 45
python3 scripts/entra_signin.py --action admin-activity
```

Use this to detect:
- legacy authentication usage
- break-glass account usage
- stale/inactive privileged accounts
- suspicious admin sign-in patterns

Interpretation:
- Any break-glass sign-in = immediate review
- Admin inactivity >45 days = disable candidate
- Legacy auth attempts = remediation required

### generate_report.py — Identity ML2 Report

```bash
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/identity-report.html
```

Weekly artifact for assessors: MFA posture, admin privilege posture, CA policy status, findings, recommendations.

### demo_generate.py — Synthetic Identity Data

```bash
python3 scripts/demo_generate.py --output ./demo --full-pipeline
```

Use for testing/demo only. Never mix with tenant evidence.
