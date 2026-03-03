# HEARTBEAT.md — VM+PM Bot

On each heartbeat cycle, work through this checklist in order. Skip checks that aren't due yet.

## 🔴 Every Cycle (Critical)

### 1. CISA KEV Check
```bash
python3 scripts/vuln_prioritise.py --action kev-check
```
If ANY tenant vulnerability matches a CISA KEV entry added in the last 48 hours:
- **Immediately generate a P1 alert**
- Include: CVE, affected software, number of exposed endpoints, ML2 patch deadline (48 hours from KEV publication)
- Update MEMORY.md with the finding

### 2. Overdue Patch Check
Review current patch compliance data. Flag:
- Any **critical/exploited** patches not applied within **48 hours** → ML2 VIOLATION
- Any **non-critical** patches not applied within **2 weeks** → ML2 VIOLATION
- Any patches in 24-48 hour window → approaching deadline, warn

If violations found, escalate. If approaching deadline, note in MEMORY.md.

## 🟡 Daily Checks

### 3. Device Inventory Refresh
```bash
python3 scripts/graph_devices.py --action list
```
Compare device count to MEMORY.md baseline. Flag:
- New devices (may not have policies applied yet)
- Missing devices (may have been decommissioned or gone offline)
- Stale devices (>14 days since last check-in)

### 4. Patch Compliance Report
```bash
python3 scripts/graph_patches.py --action compliance-report
```
Record compliance percentage in MEMORY.md. Track trend:
- Improving → note and continue
- Declining → investigate and flag
- Stable at 100% → verify scope (are all devices included?)

### 5. Vulnerability Scan (MDVM)
```bash
python3 scripts/graph_mdvm.py --action scan
```
If using MDVM (E5 tenant), pull latest vulnerability data. Run through prioritisation:
```bash
python3 scripts/vuln_prioritise.py --action prioritise --input latest-vulns.json
```

## 🟢 Weekly Checks

### 6. Vulnerability Scan (Greenbone)
```bash
python3 scripts/greenbone_scan.py --action start-scan
```
Only if using Greenbone (E3 tenant). Requires `E8CR_ENABLE_CHANGES=true`.

### 7. Stale Device Audit
```bash
python3 scripts/graph_patches.py --action stale-devices --days 14
```
Devices not checking in for 14+ days are invisible to patching. They may be:
- Offline (employee on leave — note and monitor)
- Decommissioned (should be removed from Intune)
- Compromised (investigate)

### 8. Weekly Compliance Report
```bash
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/weekly-report.html
```
Generate the full HTML report. This is the primary evidence artifact.

## 🔵 Monthly Checks

### 9. Unsupported Software Audit
Check for any applications or operating systems that are end-of-life (no vendor support). ML2 requires removal.

### 10. Full Evidence Snapshot
Export all scan data, compliance reports, and findings to the evidence/ directory. This is the monthly evidence pack for assessors.

### 11. MEMORY.md Review
Review MEMORY.md for:
- Stale exceptions that should be re-evaluated
- Open findings that have been resolved (update status)
- Baseline drift (compare current state to last month's baseline)

## After Each Check

Update MEMORY.md with:
- What was checked
- What was found (or "clean — no new findings")
- Any actions taken or escalations raised
- Current compliance score
