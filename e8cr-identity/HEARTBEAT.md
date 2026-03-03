# HEARTBEAT.md — Identity Bot

On each heartbeat cycle, execute checks in priority order.

## 🔴 Every Cycle (Critical)

1. **Admin MFA gap check**
   - If any privileged account lacks MFA, escalate immediately (P1).

2. **Break-glass sign-in check**
   - Any break-glass account activity requires immediate investigation log.

## 🟡 Every 6 Hours

3. **MFA coverage scan**
```bash
python3 scripts/entra_mfa.py --action coverage
```

4. **Legacy auth scan**
```bash
python3 scripts/entra_signin.py --action legacy-auth
```

## 🟢 Daily

5. **Admin role audit**
```bash
python3 scripts/entra_roles.py --action list
```

6. **Conditional Access audit**
```bash
python3 scripts/entra_ca.py --action audit
```

7. **Admin activity review**
```bash
python3 scripts/entra_signin.py --action admin-activity
```

## 🔵 Weekly

8. **Inactive admin detection (>45 days)**
```bash
python3 scripts/entra_signin.py --action inactive-admins --days 45
```

9. **Generate weekly identity report**
```bash
python3 scripts/generate_report.py --input ./evidence/ --output ./reports/identity-report.html
```

## Monthly

10. **Exception register review**
- Review each documented MFA/admin exception for expiry
- Confirm compensating controls still exist

11. **Baseline refresh**
- Update MEMORY.md with latest MFA %, admin count, CA policy snapshot

## After each run

Update MEMORY.md:
- timestamp
- key findings
- open violations
- actions/recommendations
