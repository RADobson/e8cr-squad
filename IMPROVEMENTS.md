# E8CR Squad — Improvement Plan (Pre-Release)

**Date:** 2026-03-02
**Reviewed by:** Ernie (full repo audit)

---

## 🔴 CRITICAL (Must fix before release)

### 1. Missing scripts referenced in SKILL.md (Identity Bot)
The identity SKILL.md documents 7 commands that reference scripts that **don't exist**:
- `scripts/entra_signin.py` — 5 commands (legacy auth, risky sign-ins, break-glass, admin activity, inactive accounts)
- `scripts/identity_report.py` — 2 commands (weekly + executive report generation)

**Only 3 scripts actually exist:** `entra_mfa.py`, `entra_roles.py`, `entra_ca.py`

This is embarrassing if someone clones the repo and follows the SKILL.md. We need to either:
- (a) Build the missing scripts, or
- (b) Remove the references from SKILL.md

**Recommendation:** Build them. They're important functionality (sign-in analysis is core to ML2 identity auditing) and the identity bot feels incomplete without them.

### 2. `__pycache__` directories committed to repo
4 `__pycache__` directories with `.pyc` files are in the repo:
- `e8cr-backup/scripts/__pycache__/`
- `e8cr-edr/scripts/__pycache__/`
- `e8cr-vmpm/scripts/__pycache__/`

Need to: `git rm -r` them and add `__pycache__/` to `.gitignore` (already in .gitignore but they were committed before it was added).

### 3. Identity bot has no `generate_report.py`
The identity demo generates JSON files but there's no HTML report generator (unlike all other bots). The demo folder has `identity/mfa-audit.json`, `identity/role-audit.json`, `identity/ca-audit.json` but no `identity-report.html` — even though the SKILL.md references `identity_report.py`.

**This means there's no visual demo output for the identity bot.** Someone clicking through the demo/ folder sees reports for every bot except identity.

### 4. Fragile cross-bot dependency via `sys.path.insert`
Every bot imports `graph_auth.py` from `e8cr-vmpm/scripts/` using `sys.path.insert` hacks:
```python
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "..", "e8cr-vmpm", "scripts"))
from graph_auth import get_env, get_token
```

This:
- Breaks if someone clones only one bot folder
- Is fragile and unpythonic
- Makes the dependency invisible

**Fix:** Extract `graph_auth.py` into a shared top-level `shared/` directory (or a proper Python package). All bots import from there.

---

## 🟡 IMPORTANT (Should fix before release)

### 5. No `requirements.txt` or dependency list
The scripts import:
- `python-gvm` + `lxml` (Greenbone only)
- Standard library only for everything else (urllib, json, argparse)

But there's no `requirements.txt` documenting this. Someone trying to run the Greenbone scanner will get an unhelpful ImportError.

### 6. No top-level architecture diagram or bot relationship map
README lists the bots but doesn't explain:
- How they relate to each other
- Which Essential Eight controls each covers
- The shared auth pattern
- How to deploy as OpenClaw skills vs standalone scripts

A simple diagram or table would help a lot.

### 7. Demo report visual quality is inconsistent
- `vmpm/weekly-report.html` — **polished** (full CSS, professional layout, colour-coded)
- `edr/edr-report.html` — **polished** (good CSS, tag-based layout)
- `appcontrol/appcontrol-report.html` — **basic** (minimal CSS, monospaced sections)
- `backup/backup-report.html` — **basic** (table-based, minimal styling)
- `identity/` — **no HTML report at all**

For a "free gift" release, visuals matter. The appcontrol and backup reports need a styling pass to match vmpm/edr quality. Identity needs a report at all.

### 8. No CONTRIBUTING.md or CODE_OF_CONDUCT.md
Standard OSS hygiene. Signals professionalism. Quick to add.

### 9. Safe mode guardrails only cover some scripts
Current safe mode (`E8CR_ENABLE_CHANGES`) protects:
- EDR: defender_response.py (isolate, block, restrict) ✅
- EDR: defender_alerts.py (update_alert_status) ✅
- VMPM: greenbone_scan.py (create_target, start_scan) ✅

**Not yet protected:**
- greenbone_scan.py `start_task()` call inside `start_scan()` — the `gmp.start_task(task_id)` line
- Any future remediation scripts
- The SKILL.md files don't mention safe mode at all

### 10. No GitHub repo metadata
Missing:
- Topics/tags (essential-eight, cybersecurity, openclaw, compliance, etc.)
- Description (set via `gh repo edit`)
- Social preview image
- GitHub Pages for demo reports (would make sharing way easier)

---

## 🟢 NICE TO HAVE (Post-release or V2)

### 11. No tests
Zero test files. For OSS credibility, even basic smoke tests (can demo_generate run without errors? does safe mode actually block?) would help.

### 12. No CI/CD
No GitHub Actions workflow. Could add:
- Lint (ruff/flake8)
- Run demo_generate for all bots (smoke test)
- Check for `__pycache__` or secrets

### 13. Duplicate `graph_get()` implementations
`intune_appcontrol.py`, `intune_hardening.py`, `intune_macros.py` all define their own `graph_get()` function (identical code). Should be shared.

### 14. Inconsistent CLI patterns
- VMPM uses `--action` (e.g., `--action compliance-report`)
- AppControl uses `--mode` (e.g., `--mode audit`)
- Backup uses `--mode`
- EDR uses `--mode` for some, positional for others

Should standardise on one pattern (`--action` is more descriptive).

### 15. No "run all bots" orchestrator
No top-level script to run all 5 bots in sequence and produce a unified compliance report. This would be the "wow" demo: one command → full E8 ML2 readiness assessment.

### 16. Report branding is hardcoded
Reports say "E8CR" everywhere. For white-labelling (MSP use case), the company name/logo should be configurable via env var or config file.

---

## Proposed Execution Order

**Phase 1 — Critical fixes (do now):**
1. Remove `__pycache__` from git history
2. Extract shared `graph_auth.py` to `shared/` dir
3. Build missing identity scripts (`entra_signin.py`, `generate_report.py`)
4. Generate identity HTML demo report

**Phase 2 — Polish (do before LinkedIn post):**
5. Add `requirements.txt`
6. Improve appcontrol + backup report styling
7. Add architecture table to README
8. Add safe mode mentions to all SKILL.md files
9. Add CONTRIBUTING.md
10. Set GitHub repo topics + description

**Phase 3 — "Wow" factor (do for viral potential):**
11. Build unified `run_all.py` orchestrator
12. Add GitHub Actions CI
13. Standardise CLI patterns
14. Add configurable branding
