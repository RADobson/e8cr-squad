# Essential Eight ML2 Requirements — Application Control, Office Macros, User App Hardening

Source: ASD Essential Eight Maturity Model (Cyber.gov.au)

## Application Control — ML2 (Intent)

Prevent execution of unapproved and malicious code.

At ML2, organisations should:
- Implement application control for user workstations and servers.
- Use a controlled allowlist approach (WDAC/AppLocker or equivalent).
- Minimise exceptions and scope them tightly.
- Collect telemetry in audit mode before enforcement.
- Remove unsupported/end-of-life applications.

Evidence typically includes:
- Policy configuration (what is allowed/blocked)
- Scope/assignments (which devices/groups)
- Enforcement state (audit vs enforce)
- Exception register with approvals

## Configure Microsoft Office Macro Settings — ML2 (Intent)

Prevent macro-enabled initial access.

At ML2, organisations should:
- Block macros from the internet / untrusted sources.
- Allow macros only from trusted locations or signed sources.
- Minimise and document macro exceptions.

Evidence includes:
- Macro policy settings
- Device compliance
- Exception list

## User Application Hardening — ML2 (Intent)

Harden user-facing applications that are common exploit targets.

At ML2, organisations should:
- Harden web browsers (disable risky features, enforce security settings).
- Harden email clients and Office settings.
- Harden PDF readers / scripting.
- Keep hardening consistent across endpoints.

Evidence includes:
- Hardening profiles
- Compliance posture
- Drift history
