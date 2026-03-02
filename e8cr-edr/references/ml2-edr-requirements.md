# EDR — ML2 Requirements Reference

While EDR isn't explicitly one of the Essential Eight controls, it's increasingly treated as an implied requirement for ML2 assessment. Assessors look for evidence of endpoint detection and response capability.

## What Assessors Look For

1. **Endpoint visibility** — Can you demonstrate awareness of what's running on endpoints?
2. **Alert monitoring** — Are security alerts being reviewed and actioned?
3. **Incident response** — Can you show a process for responding to detected threats?
4. **Evidence of operations** — Logs of triage decisions, response actions, escalations
5. **Containment capability** — Can you isolate compromised devices?

## ML2 Controls EDR Supports

| E8 Control | How EDR Helps |
|---|---|
| Application Control | Detects policy violations, blocked execution events |
| Patch Management | Identifies exploitation of unpatched vulnerabilities |
| Restrict Admin Privileges | Detects misuse of privileged accounts |
| MFA | Detects credential theft and unauthorized access |
| Regular Backups | Detects ransomware before it reaches backup systems |

## Evidence Pack Contents

- Daily/weekly alert triage summaries
- Incident reports with timeline and response actions
- Auto-resolution audit trail (false positive handling)
- Containment action logs with justification
- IOC blocking records
- Trending TTP analysis

## Operational Cadence

- **Continuous:** Alert monitoring (polling every 5 minutes)
- **Hourly:** Queue review, ensure no stuck alerts
- **Daily:** Operations summary report
- **Weekly:** Security posture report, trending analysis
- **Monthly:** Evidence pack for compliance
