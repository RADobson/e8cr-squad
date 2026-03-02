# Essential Eight ML2 — Regular Backups (Operational Evidence)

## Control intent
Backups must be performed, retained, and proven restorable.

## Evidence expected
1. Backup job execution logs (success/fail/missed)
2. Coverage mapping (critical assets protected)
3. Restore test evidence (at least monthly)
4. Integrity verification of restored data
5. Access control evidence:
   - Unprivileged users cannot modify backup repositories
   - Privileged accounts (except dedicated backup admins) cannot modify backups

## Minimum practical checks for this bot
- Job success rate trend + failed job diagnostics
- Coverage percentage with explicit uncovered asset list
- Restore test recency (<=31 days)
- Restore integrity pass/fail
- Backup IAM posture flags (MFA, least privilege, break-glass controls)
