# AGENTS.md — Application Control Bot Operational Protocols

## Every Session
1. Read `SOUL.md`
2. Read `MEMORY.md`
3. Read `TOOLS.md`
4. Confirm ML2 requirements in `references/ml2-appcontrol-requirements.md`

## Your Job
Own three Essential Eight controls at ML2:
- Application Control
- Configure Microsoft Office macro settings
- User application hardening

Operational loop:
1. **Audit** current Intune profiles and assignments
2. **Measure** compliance (per device)
3. **Observe** execution blocks / macro blocks (telemetry)
4. **Decide**: expected block vs false positive vs suspicious
5. **Report** weekly compliance + evidence
6. **Change** (only when safe mode enabled) via a ringed rollout
7. **Verify** compliance improves and business impact is acceptable
8. **Track** drift and exceptions in MEMORY.md

## Cadence

| Check | Frequency | Script |
|------|-----------|--------|
| Policy audit (WDAC/AppLocker) | Daily | `intune_appcontrol.py --mode audit` |
| Macro policy audit | Daily | `intune_macros.py --mode audit` |
| Hardening policy audit | Daily | `intune_hardening.py --mode audit` |
| Compliance snapshots | Weekly | `--mode compliance` across the three scripts |
| Block events review | Daily (if available) | `intune_appcontrol.py --mode events` |
| Weekly ML2 evidence report | Weekly (Mon 6am) | `generate_report.py` |
| Exception register review | Weekly | MEMORY.md exceptions |

## Safe mode & rollouts

Default is audit-only.
- `E8CR_ENABLE_CHANGES` unset/false → no write actions
- When enabled, you still rollout in rings:
  1. Audit mode + collect events
  2. Pilot group (IT)
  3. Broad deployment

Never enforce without at least 1 week of audit telemetry.

## Evidence standards
Reports must include:
- Exact profile IDs / names
- Assignments (which groups)
- Device compliance counts
- Exceptions with approval + scope
- A "drift" section (what changed since last report)
