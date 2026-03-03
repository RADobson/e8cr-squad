# SOC/XDR Migration Recovery Plan (from removed `e8cr-edr`)

## Why this exists
`e8cr-edr/` was removed before SOC Squad migration work was completed.
This document defines a safe, repeatable recovery path from git history.

## Recovery objective
- Recover legacy EDR bot code into a **new** migration workspace (not back into E8CR runtime path).
- Refactor into SOC-aligned **XDR** package with clear ownership boundaries.

## Source commits
Use pre-removal commits as truth source:
- `c9015a7` (EDR references still present)
- `798dac7`
- `a9afcdd`

## Step 1 — Restore legacy code snapshot
From `open-source/e8cr-squad`:

```bash
mkdir -p soc-migration/legacy-edr
for f in $(git ls-tree -r --name-only c9015a7 e8cr-edr); do
  mkdir -p "soc-migration/legacy-edr/$(dirname "$f")"
  git show "c9015a7:$f" > "soc-migration/legacy-edr/$f"
done
```

Result: frozen legacy source at `soc-migration/legacy-edr/e8cr-edr/*`.

## Step 2 — Build new XDR package shell
Target path:
- `soc-migration/e8cr-xdr/`

Structure:

```
e8cr-xdr/
├── SKILL.md
├── SOUL.md
├── AGENTS.md
├── MEMORY.md
├── TOOLS.md
├── HEARTBEAT.md
├── bot.contract.yaml
├── state/
├── schemas/
└── scripts/
```

## Step 3 — Map old EDR scripts to XDR responsibilities
| Legacy EDR | New XDR domain |
|---|---|
| defender_alerts.py | unified detection ingestion (MDE + Sentinel + identity signals) |
| incident_correlator.py | cross-signal correlation + attack-chain stitching |
| defender_response.py | response orchestration with approval gates |
| generate_report.py | incident + control-evidence reporting |

## Step 4 — Introduce parity with other bots
Before XDR is considered usable, include:
- `run_cycle.py`
- `drift_detect.py`
- `update_memory.py`
- schema validation + contract check
- signed evidence pack generation

## Step 5 — Safety constraints
- XDR starts in **audit-only / recommendation-only** mode.
- Containment actions require explicit enable flag and approval policy.

## Done criteria
1. Legacy snapshot restored and immutable.
2. New XDR package created with autonomous artifact set.
3. CI validates contract + schemas + demo outputs.
4. No dependency on deleted `e8cr-edr/` runtime path.
