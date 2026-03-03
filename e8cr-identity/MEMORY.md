# MEMORY.md — Identity Bot

## Tenant Profile

- **Tenant ID:** (set after first connection)
- **Tenant name:** (set after first connection)
- **Total user accounts:** (count from first audit)
- **Admin accounts:** (count and list from first audit)
- **PIM available:** (yes/no — requires Entra ID P2)
- **Break-glass accounts:** (list — should be exactly 2)

## Current Compliance State

### Multi-factor Authentication — ML2 Status: NOT YET ASSESSED
- MFA coverage: unknown
- MFA method distribution: unknown
- Users without MFA: unknown
- Admin accounts without MFA: unknown

### Restrict Admin Privileges — ML2 Status: NOT YET ASSESSED
- Total admin role assignments: unknown
- Standing vs just-in-time: unknown
- Inactive admins (>45 days): unknown
- Admin accounts used for non-admin tasks: unknown

## Admin Roster

Track every admin account here after first audit:
```
| UPN | Roles | MFA Status | PIM/Standing | Last Sign-in | Notes |
|-----|-------|------------|-------------|-------------|-------|
```

(Not yet populated — will fill after first admin role audit)

## MFA Baseline

```
### YYYY-MM-DD MFA Baseline
- Total accounts: X
- MFA registered: Y (Z%)
- Without MFA: N
  - Within grace period (<48h): N
  - Service accounts (documented exception): N
  - VIOLATIONS: N [list UPNs]
- Method distribution:
  - Authenticator app: N
  - FIDO2 key: N
  - Phone (SMS): N
  - Other: N
```

(Not yet populated)

## Conditional Access Policies

Track CA policy state for drift detection:
```
### YYYY-MM-DD CA Policy Snapshot
| Policy Name | State | Targets | Grant Controls | Exclusions |
```

(Not yet populated)

## Break-Glass Events

Every use of a break-glass account must be logged:
```
### YYYY-MM-DD HH:MM — Break-glass event
- Account: 
- Sign-in from:
- Reason:
- Password rotated: yes/no
- Investigated by:
```

(No events recorded)

## Known Exceptions

```
### Exception: [description]
- Account(s): [UPN list]
- Approved by: [name]
- Date: YYYY-MM-DD
- Reason: [reason]
- Compensating control: [what mitigates the risk]
- Review date: YYYY-MM-DD
```

(No exceptions recorded)

## Findings History

(Will populate after first assessment cycle)
