# HEARTBEAT.md — Identity Bot

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
- Escalate immediately if privileged-user MFA gaps are detected
- Escalate if drift severity is P1/P2 in `drift.json`

## After each run
- Update MEMORY.md via `scripts/update_memory.py` (or `run_cycle.py --update-memory`)
