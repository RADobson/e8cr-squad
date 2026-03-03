# OpenClaw Multi-Instance Deployment (4 bots on one machine)

This example shows how to run all E8CR bots on one host using **one OpenClaw instance per bot**.

## Why one instance per bot?

- Isolation of memory/context
- Independent schedules
- Independent failure domains
- Cleaner least-privilege boundaries

---

## Host sizing

Recommended baseline:
- Apple Silicon Mac mini (M4, 16GB+) or equivalent Linux host
- Node 22+
- Python 3.10+

---

## Directory layout

```bash
~/e8cr/
  vmpm/
  identity/
  appcontrol/
  backup/
```

Each folder is an independent OpenClaw workspace.

---

## 1) Install OpenClaw

```bash
curl -fsSL https://openclaw.ai/install.sh | bash
# or npm install -g openclaw@latest
```

Docs: https://docs.openclaw.ai/start/getting-started

---

## 2) Create one workspace per bot

```bash
mkdir -p ~/e8cr/{vmpm,identity,appcontrol,backup}
```

In each workspace:

```bash
cd ~/e8cr/vmpm
openclaw onboard --install-daemon
```

Repeat for each bot workspace.

---

## 3) Copy bot files into each workspace

Example for VM+PM:

```bash
cp -r /path/to/e8cr-squad/e8cr-vmpm ~/.openclaw/workspace/skills/
cp -r /path/to/e8cr-squad/shared ~/.openclaw/workspace/skills/e8cr-vmpm/
```

Repeat similarly for:
- `e8cr-identity`
- `e8cr-appcontrol`
- `e8cr-backup`

---

## 4) Configure per-bot environment

Set required variables in each workspace environment:

```bash
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
E8CR_ENABLE_CHANGES=false
```

Optional (VM+PM Greenbone):
```bash
GREENBONE_HOST=127.0.0.1
GREENBONE_PORT=9390
GREENBONE_USER=admin
GREENBONE_PASSWORD=...
```

---

## 5) Run each instance on a unique port

Example ports:
- VM+PM: `18789`
- Identity: `18790`
- AppControl: `18791`
- Backup: `18792`

```bash
# in each workspace
openclaw gateway --port 18789
```

Use each bot's own port for control UI / health checks.

---

## 6) Suggested cadence per bot

- VM+PM: daily patch + vuln checks, weekly report
- Identity: 6-hour MFA/admin checks, daily CA audit
- AppControl: daily policy audits, weekly compliance report
- Backup: daily job monitoring, weekly restore simulation

These schedules are defined in each bot's `HEARTBEAT.md`.

---

## 7) Security baseline

- Keep `E8CR_ENABLE_CHANGES=false` initially
- Run 1-2 weeks in audit mode
- Validate reports and exception handling
- Enable write actions only with change-control approval

---

## Troubleshooting

### OpenClaw command not found
Ensure install path is on `PATH`, or run through package manager (`npm`, `pnpm`, etc.).

### Graph auth failures (403/401)
Check app registration permissions and admin consent.

### Cross-bot confusion
Verify each bot is running in its own workspace/port and only has its own skill files loaded.
