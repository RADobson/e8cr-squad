---
name: e8cr-identity
description: Essential Eight Identity Bot — autonomous MFA enforcement and admin privilege management agent. Connects to Microsoft Entra ID (Azure AD) via Graph API for user auditing, MFA status, admin role management, Conditional Access policy monitoring, PIM, and sign-in log analysis. Use when operating as the Identity Bot, checking MFA coverage, auditing admin privileges, detecting legacy auth, monitoring Conditional Access, or generating E8 ML2 identity readiness reports.
---

# E8CR Identity Bot

Autonomous MFA enforcement and administrative privilege management agent for Essential Eight ML2 compliance.

## Setup

Required environment variables:
```
AZURE_TENANT_ID=<customer tenant id>
AZURE_CLIENT_ID=<app registration client id>
AZURE_CLIENT_SECRET=<app registration client secret>
```

Required Azure AD App Registration permissions (Application type):
- `User.Read.All` — Read user profiles and MFA registration
- `Directory.Read.All` — Read directory roles, groups
- `Policy.Read.All` — Read Conditional Access policies
- `AuditLog.Read.All` — Read sign-in and audit logs
- `RoleManagement.Read.All` — Read PIM role assignments
- `UserAuthenticationMethod.Read.All` — Read MFA methods

## MFA Auditing

```bash
python3 scripts/entra_mfa.py --action coverage               # MFA registration status for all users
python3 scripts/entra_mfa.py --action gaps                    # Users without MFA registered
python3 scripts/entra_mfa.py --action methods                 # MFA method breakdown (FIDO2/Authenticator/SMS/Phone)
python3 scripts/entra_mfa.py --action phishing-resistant      # Track phishing-resistant method adoption
python3 scripts/entra_mfa.py --action legacy-auth             # Detect legacy auth sign-ins (bypasses MFA)
python3 scripts/entra_mfa.py --action export --output mfa.json
```

## Admin Privilege Auditing

```bash
python3 scripts/entra_roles.py --action list                  # All admin role assignments
python3 scripts/entra_roles.py --action global-admins         # Global Admin audit
python3 scripts/entra_roles.py --action permanent             # Permanent (non-PIM) assignments
python3 scripts/entra_roles.py --action privileged-users      # Users with any admin role
python3 scripts/entra_roles.py --action service-accounts      # Service accounts with admin roles
python3 scripts/entra_roles.py --action export --output roles.json
```

## Conditional Access

```bash
python3 scripts/entra_ca.py --action list                     # All CA policies
python3 scripts/entra_ca.py --action audit                    # Check for baseline policy gaps
python3 scripts/entra_ca.py --action legacy-auth-blocked      # Verify legacy auth is blocked
python3 scripts/entra_ca.py --action export --output ca.json
```

## Sign-In Analysis

```bash
python3 scripts/entra_signin.py --action legacy               # Legacy auth sign-ins (last 7 days)
python3 scripts/entra_signin.py --action risky                 # Risky sign-ins
python3 scripts/entra_signin.py --action break-glass           # Break-glass account usage
python3 scripts/entra_signin.py --action admin-activity        # Admin account sign-in activity
python3 scripts/entra_signin.py --action inactive --days 45    # Inactive privileged accounts
```

## Reporting

```bash
python3 scripts/identity_report.py --type weekly \
    --mfa-data mfa.json --role-data roles.json --ca-data ca.json \
    --output identity-report.html

python3 scripts/identity_report.py --type executive \
    --mfa-data mfa.json --role-data roles.json \
    --output identity-exec.html
```

## ML2 Requirements Reference

See `references/ml2-identity-requirements.md` for exact ACSC ML2 criteria for MFA and Restrict Administrative Privileges controls.

## Operational Cadence

- **Continuous:** Monitor for admin role changes, CA policy modifications, break-glass sign-ins
- **Daily:** MFA coverage check, legacy auth detection, PIM activation review
- **Weekly:** Admin role audit, CA policy compliance report, identity readiness report
- **Monthly:** Full privilege review, evidence pack snapshot
