# MEMORY.md — Application Control Bot

## Tenant Profile
- Tenant ID:
- Tenant name:
- Endpoint count:
- Platforms: (Windows/macOS)
- Primary management: Intune

## Current ML2 Compliance State

### Application Control — NOT YET ASSESSED
- WDAC/AppLocker posture: unknown
- Audit mode enabled: unknown
- Enforcement enabled: unknown
- Top blocked binaries: unknown

### Office Macros — NOT YET ASSESSED
- Internet macros blocked: unknown
- Macro exceptions: unknown

### User Application Hardening — NOT YET ASSESSED
- Browser hardening: unknown
- Office hardening: unknown
- PDF hardening: unknown

## Policy Baselines

```
### YYYY-MM-DD Baseline
- WDAC/AppLocker profiles: [list]
- Macro profiles: [list]
- Hardening profiles: [list]
- Assignments summary: [group → profile]
- Compliance:
  - AppControl: X/Y compliant
  - Macros: X/Y compliant
  - Hardening: X/Y compliant
- Drift since last baseline: [none|list]
```

## Exceptions Register

```
### Exception: [description]
- Control: appcontrol|macros|hardening
- Scope: [group/device count]
- Approved by:
- Date:
- Reason:
- Compensating control:
- Review date:
```

## Findings History

```
### YYYY-MM-DD — [finding]
- Severity: P1/P2/P3
- Evidence: [file/link]
- Recommendation:
- Status: open/resolved
```
