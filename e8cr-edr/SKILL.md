---
name: e8cr-edr
description: Essential Eight EDR Operator Bot — autonomous alert triage, threat intel enrichment, and containment orchestration for Microsoft Defender for Endpoint.
---

# E8CR EDR Operator Bot

Autonomous security operations agent for **Endpoint Detection & Response (EDR)** monitoring and response.

## What it covers
1. Alert ingestion from Microsoft Defender for Endpoint
2. Threat intelligence enrichment (OSINT, reputation, MITRE mapping)
3. Alert triage and risk scoring
4. Autonomous containment decisions (bounded by policy)
5. Incident evidence generation for auditors

## Scripts

### Defender alert ingestion
```bash
python3 scripts/defender_alerts.py --mode list
python3 scripts/defender_alerts.py --mode list --status unresolved
python3 scripts/defender_alerts.py --mode detail --alert-id <id>
```

### Threat intelligence enrichment
```bash
python3 scripts/threat_intel.py --hash <sha256>
python3 scripts/threat_intel.py --ip <ip-address>
python3 scripts/threat_intel.py --domain <domain>
python3 scripts/threat_intel.py --url <url>
```

### Alert triage and scoring
```bash
python3 scripts/triage.py --input /path/alerts.json --output /path/triaged.json
```

### Autonomous response decisions
```bash
python3 scripts/response_engine.py --input /path/alert.json --mode evaluate
python3 scripts/response_engine.py --input /path/alert.json --mode execute
```

### Evidence/incident report
```bash
python3 scripts/generate_report.py --input /tmp/e8cr-demo/edr --output edr-report.html
python3 scripts/generate_report.py --input /tmp/e8cr-demo/edr --output edr-report.html --type executive
```

### Demo data generator
```bash
python3 scripts/demo_generate.py --output /tmp/e8cr-demo/edr
python3 scripts/demo_generate.py --output /tmp/e8cr-demo/edr --full-pipeline
```

## Operational cadence
- Continuous: monitor unresolved alerts
- Real-time: triage high-severity alerts (< 5 min)
- Daily: evidence export for audit trail
- Weekly: threat intelligence update + tuning

## ML2 checks
- Alert response capability demonstrated
- Threat intel integration working
- Autonomous containment within policy bounds
- Incident evidence documented and retained
