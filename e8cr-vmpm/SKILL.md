---
name: e8cr-vmpm
description: Essential Eight VM+PM Bot — autonomous vulnerability management and patch management agent. Connects to Microsoft Graph (Intune) for patch compliance, Greenbone/OpenVAS for vulnerability scanning, and CISA KEV/EPSS for prioritisation. Use when operating as the VM+PM bot, checking patch compliance, running vulnerability scans, prioritising vulnerabilities, generating E8 ML2 readiness reports, or managing patching workflows.
---

# E8CR VM+PM Bot

Autonomous vulnerability and patch management agent for Essential Eight ML2 compliance.

## Setup

Required environment variables:
```
AZURE_TENANT_ID=<customer tenant id>
AZURE_CLIENT_ID=<app registration client id>
AZURE_CLIENT_SECRET=<app registration client secret>
GREENBONE_HOST=<greenbone host, default: 127.0.0.1>
GREENBONE_PORT=<greenbone port, default: 9390>
GREENBONE_USER=<greenbone username, default: admin>
GREENBONE_PASSWORD=<greenbone password>
```

## Microsoft Graph Integration

### Authentication
Run `scripts/graph_auth.py` to obtain an access token. Uses client credentials flow (app-only, no user interaction).

Required Azure AD App Registration permissions (Application type):
- `DeviceManagementManagedDevices.Read.All` — Read Intune devices + compliance
- `DeviceManagementConfiguration.Read.All` — Read device configuration/policies

### Available Operations

**Device inventory:**
```bash
python3 scripts/graph_devices.py --action list
python3 scripts/graph_devices.py --action list --filter noncompliant
python3 scripts/graph_devices.py --action detail --device-id <id>
```

**Patch compliance:**
```bash
python3 scripts/graph_patches.py --action compliance-report
python3 scripts/graph_patches.py --action update-rings
python3 scripts/graph_patches.py --action stale-devices --days 14
```

## Vulnerability Scanning — Choose Source

The bot supports two vulnerability data sources depending on customer licensing:

### E5 Customers → Microsoft Defender Vulnerability Management (MDVM)
Already in their licence. No additional scanning infrastructure needed.

```bash
python3 scripts/graph_mdvm.py --action vulnerabilities                    # All vulns
python3 scripts/graph_mdvm.py --action vulnerabilities --severity critical # Critical only
python3 scripts/graph_mdvm.py --action software                           # Software inventory
python3 scripts/graph_mdvm.py --action software --eol-only                # EOL software
python3 scripts/graph_mdvm.py --action recommendations                    # Security recommendations
python3 scripts/graph_mdvm.py --action machines                           # Machine exposure scores
python3 scripts/graph_mdvm.py --action machines --exposure high            # High exposure only
python3 scripts/graph_mdvm.py --action export --output mdvm-export.json   # Full export
python3 scripts/graph_mdvm.py --action convert --output scan-results.json # Convert to standard format
```

Additional API permissions required (Application):
- `Vulnerability.Read.All`
- `Software.Read.All`
- `SecurityRecommendation.Read.All`
- `Machine.Read.All`

The `convert` action outputs MDVM data in the same format as Greenbone results, so the prioritisation and reporting pipeline works identically with either source.

### E3 Customers → Greenbone/OpenVAS (on-device)
Runs locally on the bot's hardware. Requires `python-gvm` and a Greenbone instance.

```bash
python3 scripts/greenbone_scan.py --action targets        # List scan targets
python3 scripts/greenbone_scan.py --action create-target --name "Corp LAN" --hosts "192.168.1.0/24"
python3 scripts/greenbone_scan.py --action scan --target-id <id>    # Start scan
python3 scripts/greenbone_scan.py --action status --task-id <id>    # Check scan status
python3 scripts/greenbone_scan.py --action results --task-id <id>   # Get results
python3 scripts/greenbone_scan.py --action results --task-id <id> --format json  # Machine-readable
```

## Vulnerability Prioritisation

Enriches scan results with real-world exploitability data:
```bash
python3 scripts/vuln_prioritise.py --results-file <greenbone_results.json>
python3 scripts/vuln_prioritise.py --cve CVE-2024-1234    # Single CVE lookup
```

Sources:
- **CISA KEV** (Known Exploited Vulnerabilities) — actively exploited in the wild
- **EPSS** (Exploit Prediction Scoring System) — probability of exploitation in next 30 days
- Combines with asset context (internet-facing, business criticality) for final priority score

## Reporting

Generate E8 ML2 readiness reports:
```bash
python3 scripts/generate_report.py --type weekly --output report.html
python3 scripts/generate_report.py --type evidence-pack --output evidence/
python3 scripts/generate_report.py --type executive --output exec-summary.html
```

## ML2 Requirements Reference

See `references/ml2-patch-requirements.md` for exact ACSC ML2 criteria for Patch Applications and Patch Operating Systems controls.

## Operational Cadence

- **Daily:** Patch compliance check, quick vuln scan (priority subnets)
- **Weekly:** Full vuln scan, delta report, patch compliance report
- **Monthly:** Evidence pack snapshot, executive summary, trending analysis
