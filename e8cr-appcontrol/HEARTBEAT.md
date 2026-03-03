# HEARTBEAT.md — Application Control Bot

## Every Cycle (Critical)
- Detect drift: if key Intune profiles are deleted/disabled → escalate
- Detect new broad exclusions or exceptions → escalate

## Daily
```bash
python3 scripts/intune_appcontrol.py --mode audit
python3 scripts/intune_macros.py --mode audit
python3 scripts/intune_hardening.py --mode audit
```
- Update MEMORY.md baselines if profiles or assignments changed

## Weekly
```bash
python3 scripts/intune_appcontrol.py --mode compliance
python3 scripts/intune_macros.py --mode compliance
python3 scripts/intune_hardening.py --mode compliance
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/appcontrol-report.html
```

## Monthly
- Review exception register (scope shrink + expiry)
- Identify unsupported applications that need removal

## After each run
Update MEMORY.md:
- timestamps
- compliance numbers
- drift summary
- open findings
