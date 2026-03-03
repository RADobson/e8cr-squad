# HEARTBEAT.md — Application Control Bot

## Every Cycle (Critical)
- Detect drift: if key Intune profiles are deleted/disabled → escalate
- Detect new broad exclusions or exceptions → escalate

## Daily
```bash
python3 scripts/run_cycle.py --period daily
```
- This writes evidence to `evidence/YYYY-MM-DD/`, updates drift state, and appends factual memory updates.

## Weekly
```bash
python3 scripts/run_cycle.py --period weekly
python3 scripts/validate_evidence.py --evidence-dir ./evidence/YYYY-MM-DD --schemas-dir ./schemas
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
