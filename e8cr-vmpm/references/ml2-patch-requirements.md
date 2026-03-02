# Essential Eight ML2 — Patch & Vulnerability Requirements

Source: ACSC Essential Eight Maturity Model (latest)

## Patch Applications — ML2

| Requirement | Detail |
|-------------|--------|
| Internet-facing service patches (exploit exists) | Within 48 hours of release |
| Internet-facing service patches (no exploit) | Within 2 weeks of release |
| Other application patches (exploit exists) | Within 48 hours of release |
| Other application patches (no exploit) | Within 1 month of release |
| Unsupported applications | Removed |
| Vulnerability scanner | Used at least fortnightly |
| Vulnerability scanner coverage | All internet-facing services and workstations |

## Patch Operating Systems — ML2

| Requirement | Detail |
|-------------|--------|
| Internet-facing OS patches (exploit exists) | Within 48 hours of release |
| Internet-facing OS patches (no exploit) | Within 2 weeks of release |
| Workstation/server OS patches (exploit exists) | Within 48 hours of release |
| Workstation/server OS patches (no exploit) | Within 1 month of release |
| Unsupported OS versions | Not used |
| Vulnerability scanner | Used at least fortnightly |

## Key Evidence Artefacts Needed

1. Patch compliance reports with timestamps (proving 48hr/2wk/1mo SLAs)
2. Vulnerability scan results (proving fortnightly cadence)
3. Remediation records (tickets showing patch deployment + verification)
4. Exception records (business justification for any delays)
5. Asset inventory showing no unsupported software/OS
6. Scan coverage evidence (all internet-facing + workstations included)

## Vulnerability Data Source Selection

| Customer Licence | Vuln Source | Patch Source | Notes |
|---|---|---|---|
| M365 E5 / E5 Security | MDVM (Graph API) | Intune (Graph API) | Everything in Microsoft, no extra infra |
| M365 E3 / Business Premium | Greenbone (on-device) | Intune (Graph API) | Greenbone fills the MDVM gap |
| Mixed / Unknown | Greenbone (default) | Intune (Graph API) | Safe default, works for everyone |

Both sources feed into the same prioritisation pipeline (`vuln_prioritise.py`) and report generator (`generate_report.py`) via a common results format.

## Compliance Scoring Logic

For each device/application, score as:
- **Compliant** — Patched within required timeframe
- **At Risk** — Patch available, within grace period
- **Non-Compliant** — Patch overdue beyond required timeframe
- **Critical** — Known exploited vulnerability, unpatched beyond 48 hours
- **Unsupported** — Running EOL software/OS (automatic non-compliance)
