#!/usr/bin/env python3
"""Threat intelligence enrichment (sample OSINT + VirusTotal stub)."""

import argparse
import json
from datetime import datetime


def sample_hash_intel(sha256):
    if sha256.startswith("9f86d081"):
        return {
            "type": "file",
            "hash": sha256,
            "known_malware": False,
            "reputation": "trusted",
            "vt_hits": 0,
            "sandbox_detections": 0,
            "signer": "Microsoft Corporation",
            "file_name": "powershell.exe",
        }
    return {
        "type": "file",
        "hash": sha256,
        "known_malware": True,
        "reputation": "malicious",
        "vt_hits": 45,
        "sandbox_detections": 12,
        "family": "Emotet",
        "first_seen": "2023-11-15T00:00:00Z",
        "last_seen": datetime.now().isoformat() + "Z",
    }


def sample_ip_intel(ip):
    if ip == "185.220.101.34":
        return {
            "type": "ip",
            "ip": ip,
            "reputation": "malicious",
            "asn": "AS3352 Tekelec Global Services",
            "country": "NL",
            "threat_type": "Tor Exit Node",
            "known_c2": True,
            "abuse_reports": 127,
        }
    return {
        "type": "ip",
        "ip": ip,
        "reputation": "clean",
        "asn": "AS15169 Google LLC",
        "country": "US",
        "threat_type": "Cloud CDN",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--hash", help="SHA256 hash")
    p.add_argument("--ip", help="IP address")
    p.add_argument("--domain", help="Domain name")
    p.add_argument("--url", help="URL")
    args = p.parse_args()

    if args.hash:
        intel = sample_hash_intel(args.hash)
    elif args.ip:
        intel = sample_ip_intel(args.ip)
    elif args.domain:
        intel = {
            "type": "domain",
            "domain": args.domain,
            "reputation": "unknown",
            "dns_a": ["1.2.3.4"],
        }
    elif args.url:
        intel = {
            "type": "url",
            "url": args.url,
            "reputation": "unknown",
            "phishing": False,
            "malware": False,
        }
    else:
        print(json.dumps({"error": "provide --hash, --ip, --domain, or --url"}, indent=2))
        return

    intel["queried_at"] = datetime.now().isoformat() + "Z"
    print(json.dumps(intel, indent=2))


if __name__ == "__main__":
    main()
