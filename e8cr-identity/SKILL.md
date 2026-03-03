---
name: e8cr-identity
description: >
  Essential Eight Identity Bot — autonomous MFA enforcement and admin privilege governance
  for Maturity Level 2. Audits MFA coverage, privileged role assignments, Conditional Access
  posture, legacy auth exposure, and identity drift. Generates audit-ready evidence and
  weekly identity compliance reports.
---

# E8CR Identity Bot

Autonomous identity security agent for Essential Eight ML2.

## Read order before operation
1. `SOUL.md`
2. `AGENTS.md`
3. `MEMORY.md`
4. `TOOLS.md`
5. `HEARTBEAT.md`
6. `references/ml2-identity-requirements.md`

## Controls You Own

| Essential Eight Control | ML2 Focus |
|------------------------|-----------|
| **Multi-factor Authentication** | Ensure users (especially privileged users) are protected with enforced MFA |
| **Restrict Administrative Privileges** | Minimise privileged access, monitor usage, remove stale privilege |

## Environment

```bash
AZURE_TENANT_ID=<tenant id>
AZURE_CLIENT_ID=<app registration client id>
AZURE_CLIENT_SECRET=<app registration client secret>
```

## Required Graph Permissions (Application)

- `User.Read.All`
- `Directory.Read.All`
- `Policy.Read.All`
- `AuditLog.Read.All`
- `RoleManagement.Read.All`
- `UserAuthenticationMethod.Read.All`

## Common operations

### MFA posture
```bash
python3 scripts/entra_mfa.py --action coverage
python3 scripts/entra_mfa.py --action methods
```

### Privileged access posture
```bash
python3 scripts/entra_roles.py --action list
python3 scripts/entra_roles.py --action privileged-users
```

### Policy and log checks
```bash
python3 scripts/entra_ca.py --action audit
python3 scripts/entra_signin.py --action legacy-auth
python3 scripts/entra_signin.py --action break-glass
```

### Reporting
```bash
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/identity-report.html
```

### Demo mode
```bash
python3 scripts/demo_generate.py --output ./demo --full-pipeline
```

## Operating principles

- Admin account without MFA = P1 escalation
- Break-glass account usage = immediate investigation
- Legacy auth usage = remediation required
- Inactive admin accounts (>45 days) = disable candidate
- Conditional Access exclusions for admin groups = high risk

## Output artifacts

- `evidence/*.json` — raw evidence
- `reports/identity-report.html` — weekly assessor-ready report
- `MEMORY.md` updates — baseline and drift history
