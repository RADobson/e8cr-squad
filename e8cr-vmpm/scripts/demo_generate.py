#!/usr/bin/env python3
"""Generate realistic synthetic data for E8CR VM+PM demo.

Creates a complete dataset for a fictional 150-seat company "Meridian Civil Group"
(a Queensland civil construction firm in the federal gov supply chain).

Usage:
    python3 demo_generate.py --output /tmp/e8cr-demo/
    python3 demo_generate.py --output /tmp/e8cr-demo/ --full-pipeline  # Generate + prioritise + report

Produces:
    - patch-compliance.json (Intune device inventory + compliance)
    - scan-results.json (vulnerability scan results)
    - Then optionally runs vuln_prioritise.py + generate_report.py on them
"""

import json
import os
import sys
import random
import argparse
import subprocess
from datetime import datetime, timedelta, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Company Profile ---
COMPANY = "Meridian Civil Group"
DOMAIN = "meridiancivil.com.au"
SEATS = 148

# Departments with realistic sizing
DEPARTMENTS = {
    "exec": {"prefix": "EXEC", "count": 6, "type": "laptop", "users": [
        "ceo", "cfo", "coo", "gm.projects", "gm.operations", "ea.ceo"
    ]},
    "finance": {"prefix": "FIN", "count": 12, "type": "desktop", "users": [
        "accounts.payable", "accounts.receivable", "payroll", "finance.mgr",
        "bookkeeper.1", "bookkeeper.2", "procurement.1", "procurement.2",
        "contracts.admin", "finance.analyst", "billing", "expenses"
    ]},
    "projects": {"prefix": "PROJ", "count": 18, "type": "laptop", "users": [
        "pm.smith", "pm.jones", "pm.chen", "pm.williams", "pm.brown",
        "pm.taylor", "pm.wilson", "pm.anderson", "pm.thomas", "pm.jackson",
        "estimator.1", "estimator.2", "estimator.3", "planner.1", "planner.2",
        "drafting.1", "drafting.2", "drafting.3"
    ]},
    "site": {"prefix": "SITE", "count": 35, "type": "tablet", "users": [
        *[f"supervisor.{i}" for i in range(1, 11)],
        *[f"foreman.{i}" for i in range(1, 11)],
        *[f"safety.{i}" for i in range(1, 6)],
        *[f"qc.{i}" for i in range(1, 6)],
        *[f"site.admin.{i}" for i in range(1, 5)],
    ]},
    "engineering": {"prefix": "ENG", "count": 14, "type": "desktop", "users": [
        "chief.engineer", "structural.1", "structural.2", "civil.1", "civil.2",
        "civil.3", "geotech.1", "geotech.2", "environmental.1", "environmental.2",
        "cad.1", "cad.2", "cad.3", "bim.mgr"
    ]},
    "it": {"prefix": "IT", "count": 4, "type": "laptop", "users": [
        "it.manager", "sysadmin", "helpdesk.1", "helpdesk.2"
    ]},
    "hr": {"prefix": "HR", "count": 6, "type": "desktop", "users": [
        "hr.manager", "recruitment", "whs.officer", "training", "hr.admin", "onboarding"
    ]},
    "fleet": {"prefix": "FLEET", "count": 8, "type": "desktop", "users": [
        "fleet.mgr", "logistics.1", "logistics.2", "logistics.3",
        "warehouse.1", "warehouse.2", "plant.1", "plant.2"
    ]},
    "shared": {"prefix": "CONF", "count": 6, "type": "desktop", "users": [
        "boardroom.1", "boardroom.2", "reception", "breakroom", "training.room", "print.station"
    ]},
    "server": {"prefix": "SRV", "count": 8, "type": "server", "users": [
        "dc01", "dc02", "fileserver", "printserver", "sqlserver",
        "appserver", "backup", "rds01"
    ]},
}

# OS versions (realistic mix for an AU construction company)
OS_VERSIONS = {
    "good": [
        ("Windows", "10.0.19045.4170", 0.35),    # Win 10 22H2 (current)
        ("Windows", "10.0.22631.3296", 0.30),     # Win 11 23H2 (current)
        ("Windows", "10.0.22621.3296", 0.10),     # Win 11 22H2
    ],
    "outdated": [
        ("Windows", "10.0.19044.4170", 0.08),     # Win 10 21H2 (EOL)
        ("Windows", "10.0.19043.3570", 0.04),      # Win 10 21H1 (EOL)
    ],
    "server": [
        ("Windows Server", "10.0.20348.2340", 0.60),  # Server 2022
        ("Windows Server", "10.0.17763.5458", 0.30),   # Server 2019
        ("Windows Server", "10.0.14393.6614", 0.10),   # Server 2016 (approaching EOL)
    ],
    "tablet": [
        ("Windows", "10.0.19045.4170", 0.50),
        ("Windows", "10.0.22631.3296", 0.30),
        ("iOS", "17.3.1", 0.20),
    ],
}

# EOL versions
EOL_VERSIONS = {"10.0.19043", "10.0.19044", "10.0.14393"}

# Realistic vulnerabilities (mix of real CVEs)
VULNS = [
    # Critical - actively exploited
    {"cves": ["CVE-2024-21887"], "name": "Ivanti Connect Secure Command Injection", "severity": 9.8, "port": "443/tcp",
     "solution": "Update Ivanti Connect Secure to latest version", "hosts": ["SRV-APPSERVER"]},
    {"cves": ["CVE-2024-3400"], "name": "Palo Alto Networks PAN-OS Command Injection", "severity": 10.0, "port": "443/tcp",
     "solution": "Apply PAN-OS hotfix", "hosts": ["FW-01"]},

    # High - common Windows vulns
    {"cves": ["CVE-2024-30088"], "name": "Windows Kernel Elevation of Privilege", "severity": 8.8, "port": "",
     "solution": "Apply June 2024 Cumulative Update",
     "hosts": ["random", 12]},
    {"cves": ["CVE-2024-38063"], "name": "Windows TCP/IP Remote Code Execution", "severity": 9.8, "port": "135/tcp",
     "solution": "Apply August 2024 Cumulative Update",
     "hosts": ["random", 8]},
    {"cves": ["CVE-2024-21338"], "name": "Windows Kernel Pool Overflow", "severity": 7.8, "port": "",
     "solution": "Apply February 2024 Cumulative Update",
     "hosts": ["random", 15]},
    {"cves": ["CVE-2024-30078"], "name": "Windows Wi-Fi Driver Remote Code Execution", "severity": 8.8, "port": "",
     "solution": "Apply June 2024 Cumulative Update",
     "hosts": ["random", 6]},
    {"cves": ["CVE-2024-38178"], "name": "Windows Scripting Engine Memory Corruption", "severity": 7.5, "port": "",
     "solution": "Apply August 2024 security update",
     "hosts": ["random", 20]},

    # Medium - config/service issues
    {"cves": ["CVE-2024-6387"], "name": "OpenSSH regreSSHion Remote Code Execution", "severity": 8.1, "port": "22/tcp",
     "solution": "Update OpenSSH to 9.8p1 or later",
     "hosts": ["SRV-DC01", "SRV-DC02", "SRV-FILESERVER"]},
    {"cves": ["CVE-2023-44487"], "name": "HTTP/2 Rapid Reset Attack (DDoS)", "severity": 7.5, "port": "443/tcp",
     "solution": "Apply vendor patches for HTTP/2 implementation",
     "hosts": ["SRV-APPSERVER", "SRV-RDS01"]},
    {"cves": [], "name": "SMBv1 Protocol Enabled", "severity": 5.3, "port": "445/tcp",
     "solution": "Disable SMBv1 protocol",
     "hosts": ["random", 25]},
    {"cves": [], "name": "SSL/TLS Certificate Expired", "severity": 4.3, "port": "443/tcp",
     "solution": "Renew SSL certificate",
     "hosts": ["SRV-APPSERVER"]},
    {"cves": [], "name": "LLMNR/NBT-NS Poisoning Possible", "severity": 5.3, "port": "",
     "solution": "Disable LLMNR and NBT-NS via GPO",
     "hosts": ["random", 40]},
    {"cves": [], "name": "NTLMv1 Authentication Allowed", "severity": 5.9, "port": "",
     "solution": "Enforce NTLMv2 minimum via GPO",
     "hosts": ["random", 30]},
    {"cves": [], "name": "Windows Remote Desktop NLA Not Enforced", "severity": 4.3, "port": "3389/tcp",
     "solution": "Enable Network Level Authentication for RDP",
     "hosts": ["random", 8]},
    {"cves": [], "name": "Unquoted Service Path", "severity": 5.9, "port": "",
     "solution": "Quote service binary paths in registry",
     "hosts": ["random", 18]},

    # Low/Info
    {"cves": [], "name": "ICMP Timestamp Response Enabled", "severity": 2.1, "port": "",
     "solution": "Block ICMP timestamp at host firewall", "hosts": ["random", 60]},
    {"cves": [], "name": "TCP Timestamp Response Enabled", "severity": 1.0, "port": "",
     "solution": "Informational — consider disabling", "hosts": ["random", 80]},
    {"cves": [], "name": "DNS Server Recursive Queries Allowed", "severity": 3.5, "port": "53/udp",
     "solution": "Restrict DNS recursion to internal clients only",
     "hosts": ["SRV-DC01", "SRV-DC02"]},
]


def weighted_choice(options):
    """Pick from list of (value_a, value_b, weight) tuples."""
    r = random.random()
    cumulative = 0
    for *vals, weight in options:
        cumulative += weight
        if r <= cumulative:
            return vals if len(vals) > 1 else vals[0]
    return options[-1][:-1] if len(options[-1]) > 2 else options[-1][0]


def generate_devices():
    """Generate realistic device inventory."""
    now = datetime.now(timezone.utc)
    devices = []
    all_device_names = []

    for dept, info in DEPARTMENTS.items():
        for i, user in enumerate(info["users"]):
            device_num = str(i + 1).zfill(3)
            device_name = f"{info['prefix']}-{device_num}"
            all_device_names.append(device_name)

            device_type = info["type"]

            # Pick OS version
            if device_type == "server":
                os_name, os_ver = weighted_choice(OS_VERSIONS["server"])
            elif device_type == "tablet":
                os_name, os_ver = weighted_choice(OS_VERSIONS["tablet"])
            else:
                # 85% chance good, 15% chance outdated
                if random.random() < 0.85:
                    os_name, os_ver = weighted_choice(OS_VERSIONS["good"])
                else:
                    os_name, os_ver = weighted_choice(OS_VERSIONS["outdated"])

            # Compliance state
            is_eol = any(os_ver.startswith(eol) for eol in EOL_VERSIONS)
            if is_eol:
                compliance = "noncompliant"
            elif random.random() < 0.82:
                compliance = "compliant"
            else:
                compliance = "noncompliant"

            # Last sync — most recent, some stale
            if random.random() < 0.92:
                last_sync = now - timedelta(hours=random.randint(1, 48))
            elif random.random() < 0.7:
                last_sync = now - timedelta(days=random.randint(3, 13))
            else:
                last_sync = now - timedelta(days=random.randint(14, 45))

            # Site tablets are more likely to be stale
            if device_type == "tablet" and random.random() < 0.3:
                last_sync = now - timedelta(days=random.randint(7, 30))

            upn = f"{user}@{DOMAIN}" if device_type != "server" else f"svc.{user}@{DOMAIN}"

            devices.append({
                "id": f"dev-{dept}-{device_num}",
                "deviceName": device_name,
                "operatingSystem": os_name,
                "osVersion": os_ver,
                "complianceState": compliance,
                "lastSyncDateTime": last_sync.isoformat(),
                "enrolledDateTime": (now - timedelta(days=random.randint(30, 400))).isoformat(),
                "manufacturer": random.choice(["Dell", "Lenovo", "HP", "Microsoft"]) if device_type != "server" else "Dell",
                "model": "Latitude 5540" if device_type == "laptop" else ("OptiPlex 7010" if device_type == "desktop" else ("Surface Go 3" if device_type == "tablet" else "PowerEdge R750")),
                "userPrincipalName": upn,
                "managedDeviceOwnerType": "company",
                "department": dept,
            })

    return devices, all_device_names


def build_patch_compliance(devices):
    """Build patch compliance report from device data."""
    now = datetime.now(timezone.utc)
    cutoff_14d = now - timedelta(days=14)

    compliant = 0
    noncompliant = 0
    unknown = 0
    stale_devices = []
    eol_devices = []
    os_versions = {}

    for d in devices:
        state = d["complianceState"]
        if state == "compliant":
            compliant += 1
        elif state == "noncompliant":
            noncompliant += 1
        else:
            unknown += 1

        ver_key = f"{d['operatingSystem']} {d['osVersion']}"
        os_versions[ver_key] = os_versions.get(ver_key, 0) + 1

        sync_dt = datetime.fromisoformat(d["lastSyncDateTime"])
        if sync_dt < cutoff_14d:
            stale_devices.append({
                "deviceName": d["deviceName"],
                "lastSync": d["lastSyncDateTime"],
                "daysSinceSync": (now - sync_dt).days,
                "user": d["userPrincipalName"],
                "department": d["department"],
            })

        is_eol = any(d["osVersion"].startswith(eol) for eol in EOL_VERSIONS)
        if is_eol:
            eol_devices.append({
                "deviceName": d["deviceName"],
                "osVersion": d["osVersion"],
                "user": d["userPrincipalName"],
                "department": d["department"],
            })

    total = len(devices)
    rate = round((compliant / total) * 100, 1) if total > 0 else 0

    return {
        "generated_at": now.isoformat(),
        "company": COMPANY,
        "total_devices": total,
        "compliance_rate": rate,
        "patch_compliance": {
            "compliant": compliant,
            "noncompliant": noncompliant,
            "unknown": unknown,
        },
        "os_versions": dict(sorted(os_versions.items(), key=lambda x: -x[1])),
        "stale_count": len(stale_devices),
        "stale_devices": sorted(stale_devices, key=lambda x: -x["daysSinceSync"]),
        "eol_count": len(eol_devices),
        "eol_devices": eol_devices,
        "details": [{
            "deviceName": d["deviceName"],
            "os": d["operatingSystem"],
            "osVersion": d["osVersion"],
            "compliance": d["complianceState"],
            "lastSync": d["lastSyncDateTime"],
            "stale": (now - datetime.fromisoformat(d["lastSyncDateTime"])).days > 14,
            "eol": any(d["osVersion"].startswith(eol) for eol in EOL_VERSIONS),
            "user": d["userPrincipalName"],
            "department": d["department"],
        } for d in devices],
    }


def generate_scan_results(all_device_names):
    """Generate vulnerability scan results."""
    now = datetime.now(timezone.utc)
    # Build a subnet mapping
    subnet_base = "10.20"
    dept_subnets = {
        "EXEC": f"{subnet_base}.10", "FIN": f"{subnet_base}.11",
        "PROJ": f"{subnet_base}.12", "SITE": f"{subnet_base}.13",
        "ENG": f"{subnet_base}.14", "IT": f"{subnet_base}.15",
        "HR": f"{subnet_base}.16", "FLEET": f"{subnet_base}.17",
        "CONF": f"{subnet_base}.18", "SRV": f"{subnet_base}.1",
        "FW": f"{subnet_base}.1",
    }

    def device_to_ip(device_name):
        prefix = device_name.split("-")[0]
        num = int(device_name.split("-")[-1]) if device_name.split("-")[-1].isdigit() else random.randint(1, 254)
        subnet = dept_subnets.get(prefix, f"{subnet_base}.20")
        return f"{subnet}.{num}"

    results = []
    for vuln in VULNS:
        if vuln["hosts"][0] == "random":
            count = vuln["hosts"][1]
            hosts = random.sample(all_device_names, min(count, len(all_device_names)))
        else:
            hosts = vuln["hosts"]

        for host in hosts:
            ip = device_to_ip(host)
            results.append({
                "id": f"finding-{len(results)+1}",
                "host": ip,
                "hostname": host,
                "port": vuln["port"],
                "severity": vuln["severity"],
                "severity_label": (
                    "Critical" if vuln["severity"] >= 9.0 else
                    "High" if vuln["severity"] >= 7.0 else
                    "Medium" if vuln["severity"] >= 4.0 else
                    "Low" if vuln["severity"] > 0 else "Info"
                ),
                "name": vuln["name"],
                "oid": "",
                "cves": vuln["cves"],
                "solution": vuln["solution"],
                "description": f"Detected {vuln['name']} on {host} ({ip}). {vuln['solution']}.",
            })

    results.sort(key=lambda x: x["severity"], reverse=True)

    return {
        "exported_at": now.isoformat(),
        "scan_type": "Full and fast",
        "target": f"{subnet_base}.0.0/16",
        "total_findings": len(results),
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate E8CR demo data")
    parser.add_argument("--output", default="/tmp/e8cr-demo", help="Output directory")
    parser.add_argument("--full-pipeline", action="store_true",
                        help="Run prioritisation + report generation after data gen")
    args = parser.parse_args()

    out = args.output
    os.makedirs(out, exist_ok=True)

    print(f"Generating demo data for {COMPANY} ({SEATS} seats)...")

    # Generate devices
    devices, all_names = generate_devices()
    print(f"  {len(devices)} devices generated")

    # Build patch compliance
    patch = build_patch_compliance(devices)
    patch_file = os.path.join(out, "patch-compliance.json")
    with open(patch_file, "w") as f:
        json.dump(patch, f, indent=2)
    print(f"  Patch compliance: {patch['compliance_rate']}% "
          f"({patch['eol_count']} EOL, {patch['stale_count']} stale)")

    # Generate scan results
    scan = generate_scan_results(all_names)
    scan_file = os.path.join(out, "scan-results.json")
    with open(scan_file, "w") as f:
        json.dump(scan, f, indent=2)
    print(f"  {scan['total_findings']} vulnerability findings generated")

    # Export raw device inventory
    inv_file = os.path.join(out, "device-inventory.json")
    with open(inv_file, "w") as f:
        json.dump({"company": COMPANY, "exported_at": datetime.now(timezone.utc).isoformat(),
                    "device_count": len(devices), "devices": devices}, f, indent=2)
    print(f"  Device inventory exported")

    if args.full_pipeline:
        print("\nRunning full pipeline...")

        # Step 1: Prioritise
        prioritised_file = os.path.join(out, "prioritised.json")
        print("  Enriching with CISA KEV + EPSS...")
        subprocess.run([
            sys.executable, os.path.join(SCRIPT_DIR, "vuln_prioritise.py"),
            "--results-file", scan_file,
            "--output", prioritised_file,
        ], check=True)

        # Step 2: Weekly report
        weekly_file = os.path.join(out, "weekly-report.html")
        print("  Generating weekly report...")
        subprocess.run([
            sys.executable, os.path.join(SCRIPT_DIR, "generate_report.py"),
            "--type", "weekly",
            "--patch-data", patch_file,
            "--vuln-data", prioritised_file,
            "--output", weekly_file,
        ], check=True)

        # Step 3: Executive summary
        exec_file = os.path.join(out, "executive-summary.html")
        print("  Generating executive summary...")
        subprocess.run([
            sys.executable, os.path.join(SCRIPT_DIR, "generate_report.py"),
            "--type", "executive",
            "--patch-data", patch_file,
            "--vuln-data", prioritised_file,
            "--output", exec_file,
        ], check=True)

        # Step 4: Evidence pack
        evidence_dir = os.path.join(out, "evidence-pack")
        print("  Generating evidence pack...")
        subprocess.run([
            sys.executable, os.path.join(SCRIPT_DIR, "generate_report.py"),
            "--type", "evidence-pack",
            "--patch-data", patch_file,
            "--vuln-data", prioritised_file,
            "--output", evidence_dir,
        ], check=True)

        print(f"\n✅ Full demo pipeline complete!")
        print(f"   Output: {out}/")
        print(f"   Open: {weekly_file}")

    else:
        print(f"\nData written to {out}/")
        print(f"Run with --full-pipeline to generate reports too.")


if __name__ == "__main__":
    main()
