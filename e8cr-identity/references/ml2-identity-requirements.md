# Essential Eight ML2 — MFA & Admin Privilege Requirements

Source: ACSC Essential Eight Maturity Model (latest)

## Multi-factor Authentication — ML2

| Requirement | Detail |
|-------------|--------|
| MFA for org online services | MFA is used to authenticate users to their organisation's online services |
| MFA for third-party services | MFA is used to authenticate users to third-party online services that process/store/communicate org data |
| MFA method | Something users have AND something users know, OR something users have unlocked by something users know/are |
| Phishing-resistant MFA | Used where available, especially for privileged/admin access |
| MFA events logged | Successful and failed MFA events are logged |

## Restrict Administrative Privileges — ML2

| Requirement | Detail |
|-------------|--------|
| Privilege validation | Requests for privileged access are validated when first requested |
| No email/browsing with admin | Privileged accounts are not used for reading email and browsing the web |
| Privileged events logged | Privileged access events are logged |
| Inactive account disable | Privileged accounts are disabled after 45 days of inactivity |
| Environment separation | Privileged operating environments are not virtualised within unprivileged operating environments |

## Key Evidence Artefacts Needed

1. MFA registration report (all users, method type, registration date)
2. MFA enforcement evidence (Conditional Access policies requiring MFA)
3. Legacy auth blocking evidence (CA policy blocking legacy protocols)
4. Admin role assignment report (who has what roles, permanent vs PIM)
5. Global Admin count and justification (should be 2-4 max)
6. PIM configuration evidence (just-in-time access, activation requirements)
7. Break-glass account documentation and monitoring evidence
8. Inactive privileged account report (45-day threshold)
9. Sign-in logs showing MFA enforcement
10. Separation of admin browsing/email evidence

## Compliance Scoring Logic

### MFA Score
- **Compliant:** MFA registered + enforced via CA policy + phishing-resistant method
- **Partial:** MFA registered but not phishing-resistant (SMS/phone call)
- **Non-Compliant:** No MFA registered or no CA policy enforcing MFA
- **Critical:** Admin/privileged user without MFA

### Admin Privilege Score
- **Compliant:** Role assigned via PIM (just-in-time), active within 45 days
- **At Risk:** Permanent role assignment (not PIM), but active
- **Non-Compliant:** Permanent Global Admin, or inactive >45 days but not disabled
- **Critical:** Admin account used for email/browsing, or break-glass used without incident
