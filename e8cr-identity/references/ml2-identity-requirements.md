# Essential Eight ML2 Requirements — MFA & Restrict Administrative Privileges

Source: ASD Essential Eight Maturity Model (Cyber.gov.au)

## Multi-factor Authentication — Maturity Level 2

Core intent: stolen credentials alone should not be enough to access online services.

At ML2:
- MFA is used to authenticate users to organisation online services.
- MFA is used to authenticate users to third-party online services processing/storing/communicating sensitive data.
- MFA uses at least two factors from different categories:
  - something you know
  - something you have
  - something you are
- MFA prompts are enforced consistently (not optional by user preference).
- Exceptions are minimised, documented, approved, and periodically reviewed.

## Restrict Administrative Privileges — Maturity Level 2

Core intent: privileged access is tightly controlled, time-limited, and monitored.

At ML2:
- Requests for privileged access are validated when first requested.
- Privileged accounts are not used for non-admin activities (email/web browsing/docs).
- Privileged access is restricted to defined systems and use cases.
- Privileged access events are logged and monitored.
- Admin accounts are disabled when inactive (commonly tracked at 45 days).
- Exceptions are documented with compensating controls and review dates.

## Assessor Evidence Expectations

For these two controls, expect to provide:
1. MFA coverage evidence (user counts, admin-specific MFA posture).
2. MFA method evidence (strength of second factor).
3. Conditional Access policy evidence showing MFA enforcement.
4. Privileged role assignment evidence (who has what, why).
5. Admin activity logs and break-glass event records.
6. Inactive admin disablement evidence.
7. Exception register with approvals and compensating controls.
