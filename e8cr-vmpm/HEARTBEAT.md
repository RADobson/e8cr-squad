# HEARTBEAT.md — VM+PM Bot

## Daily
```bash
python3 scripts/run_cycle.py --period daily
```

## Weekly
```bash
python3 scripts/run_cycle.py --period weekly
python3 scripts/validate_evidence.py --evidence-dir ./evidence/YYYY-MM-DD --schemas-dir ./schemas
```

## Every Cycle (Critical)
- Escalate if drift severity is P1/P2 in `drift.json`
- Escalate if critical/exploited patch SLA breaches are detected

## After each run
- Update MEMORY.md via `scripts/update_memory.py` (or `run_cycle.py --update-memory`)
