# Essential Eight ML2 Requirements — Regular Backups

Source: ASD Essential Eight Maturity Model (Cyber.gov.au)

## Regular Backups — ML2 (Intent)

Be able to recover from ransomware, destruction, or corruption of systems and data.

At ML2, organisations should:
- Perform regular backups of important data, software, and configuration.
- Monitor backup jobs and respond to failures.
- Perform restore testing to confirm backups are recoverable.
- Protect backup systems and credentials from compromise.

## Evidence Expectations (Assessor)

An assessor will typically look for:
1. Backup schedule / job history showing backups occur regularly.
2. Monitoring/alerting evidence for failures.
3. Restore test evidence (what was tested, when, and the result).
4. Coverage evidence (what assets/data are protected; identify gaps).
5. Backup access control evidence (least privilege, separation, MFA where possible).

## Practical control mapping for this bot

This bot produces:
- Job audit evidence (JSON)
- Coverage gap evidence (JSON)
- Restore test evidence (JSON + logs)
- Weekly HTML report summarising ML2 posture
- MEMORY.md drift history and exceptions register
