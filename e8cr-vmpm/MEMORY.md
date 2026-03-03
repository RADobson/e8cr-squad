# MEMORY.md — VM+PM Bot

## Tenant Profile

- **Tenant ID:** (set after first connection)
- **Tenant name:** (set after first connection)
- **Endpoints managed:** (count from first device inventory)
- **Servers managed:** (count from first device inventory)
- **Primary OS:** (Windows 10/11 mix from inventory)
- **Microsoft licensing:** (E3/E5/Business Premium)
- **Vulnerability scanner:** (MDVM or Greenbone — set during setup)

## Current Compliance State

### Patch Applications — ML2 Status: NOT YET ASSESSED
- Last assessment: never
- Critical patches overdue: unknown
- High patches overdue: unknown
- Unsupported applications detected: unknown

### Patch OS — ML2 Status: NOT YET ASSESSED
- Last assessment: never
- Critical OS patches overdue: unknown
- Unsupported operating systems detected: unknown

## Baselines

Track baseline state here after each major scan. Format:
```
### YYYY-MM-DD Baseline
- Total endpoints: X
- Compliant: Y (Z%)
- Critical vulns: N (K on CISA KEV)
- Overdue patches: N
- Unsupported software: [list]
```

(No baselines recorded yet — will populate after first scan)

## Known Exceptions

Document any approved exceptions here:
```
### Exception: [description]
- Approved by: [name]
- Date: YYYY-MM-DD
- Reason: [reason]
- Compensating control: [if any]
- Review date: YYYY-MM-DD
```

(No exceptions recorded yet)

## Findings History

Track significant findings chronologically:
```
### YYYY-MM-DD — [finding summary]
- Severity: P1/P2/P3
- Detail: [what was found]
- Action taken: [what was done]
- Current status: [open/resolved]
```

(No findings recorded yet — will populate after first scan)

## Notes

- This file is updated automatically by the VM+PM bot after each assessment cycle
- Assessors can reference this file for a chronological view of the tenant's patching posture
- Keep entries factual and evidence-referenced
