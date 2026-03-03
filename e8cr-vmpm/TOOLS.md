# TOOLS.md — VM+PM Bot Script Reference

## Authentication

All scripts that talk to Microsoft Graph use `shared/graph_auth.py`. It handles the client credentials OAuth2 flow. You need these environment variables set:

```bash
AZURE_TENANT_ID=<tenant id>
AZURE_CLIENT_ID=<app registration client id>
AZURE_CLIENT_SECRET=<app registration client secret>
```

Verify auth works: `python3 shared/graph_auth.py --check`

If auth fails, DON'T retry silently. Flag it — permissions may have been revoked.

## Scripts

### graph_devices.py — Device Inventory

**What it does:** Pulls all Intune-managed devices with OS, compliance status, last check-in time.

```bash
# List all managed devices
python3 scripts/graph_devices.py --action list

# Filter to non-compliant only
python3 scripts/graph_devices.py --action list --filter noncompliant

# Get details for a specific device
python3 scripts/graph_devices.py --action detail --device-id <id>
```

**When to use:** Daily inventory refresh. Also run after patching to verify devices checked in.

**How to interpret:**
- `lastSyncDateTime` older than 14 days → device is stale, patching status unknown
- `complianceState: noncompliant` → investigate which policies are failing
- Count of managed devices should match expected fleet size. If significantly lower, devices may not be enrolled.

### graph_patches.py — Patch Compliance

**What it does:** Queries Intune for Windows Update compliance, update ring membership, and stale devices.

```bash
# Full compliance report
python3 scripts/graph_patches.py --action compliance-report

# Check update ring assignments
python3 scripts/graph_patches.py --action update-rings

# Find devices that haven't checked in recently
python3 scripts/graph_patches.py --action stale-devices --days 14
```

**When to use:** Daily compliance check. The compliance report is your primary evidence artifact.

**How to interpret:**
- Compare `installedPatchCount` vs `availablePatchCount` per device
- Any device with available critical patches older than 48 hours → ML2 violation
- Any device with available non-critical patches older than 2 weeks → ML2 violation
- Stale devices (>14 days no check-in) → unknown compliance, flag as risk

### graph_mdvm.py — Microsoft Defender Vulnerability Management

**What it does:** Pulls vulnerability data from MDVM (requires E5 or Defender for Endpoint P2).

```bash
# List vulnerabilities for the tenant
python3 scripts/graph_mdvm.py --action scan

# Get details for a specific CVE
python3 scripts/graph_mdvm.py --action cve-detail --cve CVE-2024-XXXXX
```

**When to use:** Daily scan for E5 tenants. This is your primary vulnerability data source if the tenant has MDVM.

**How to interpret:**
- Each vulnerability has a CVE, affected software, and exposed devices count
- Cross-reference with CISA KEV list (via vuln_prioritise.py) before prioritising by CVSS alone

### greenbone_scan.py — Greenbone/OpenVAS Vulnerability Scanner

**What it does:** Manages vulnerability scans on a local Greenbone instance. Use this for E3 tenants that don't have MDVM.

```bash
# Start a new scan
python3 scripts/greenbone_scan.py --action start-scan --target 192.168.1.0/24

# Check scan status
python3 scripts/greenbone_scan.py --action scan-status

# Get results
python3 scripts/greenbone_scan.py --action results
```

**⚠️ SAFE MODE:** `start-scan` requires `E8CR_ENABLE_CHANGES=true`. Scans actively probe the network.

**When to use:** Weekly scans minimum (ML2 requires fortnightly, but weekly is better practice).

**Additional requirements:** `pip install python-gvm lxml` (see requirements.txt)

### vuln_prioritise.py — Vulnerability Prioritisation

**What it does:** Takes vulnerability data from MDVM or Greenbone and enriches it with CISA KEV and EPSS data for real-world risk prioritisation.

```bash
# Check tenant vulns against CISA KEV
python3 scripts/vuln_prioritise.py --action kev-check

# Full prioritisation with EPSS scores
python3 scripts/vuln_prioritise.py --action prioritise --input vulns.json

# Get current CISA KEV list
python3 scripts/vuln_prioritise.py --action kev-update
```

**When to use:** After every scan. Always run this before generating a report — raw CVSS prioritisation is misleading.

**How to interpret:**
- P1 (CISA KEV match or EPSS > 0.5): patch within 48 hours, escalate immediately
- P2 (CVSS >= 7.0, not on KEV): patch within 2 weeks
- P3 (everything else): patch within 1 month
- If a KEV entry is NEW (added in last 48 hours), treat as urgent even if the vuln has been known for months

### generate_report.py — HTML Compliance Report

**What it does:** Takes scan results and compliance data and generates a professional HTML report.

```bash
# Generate weekly report from latest data
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/weekly-report.html

# Include company branding
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/ --company "Acme Corp"
```

**When to use:** Weekly (Monday 6am). Also on-demand when preparing for an assessment.

### demo_generate.py — Synthetic Data Generator

**What it does:** Generates realistic synthetic data for testing and demos. No tenant needed.

```bash
python3 scripts/demo_generate.py --output ./demo --full-pipeline
```

**When to use:** Testing, demos, development. Never mix demo data with real tenant data.
