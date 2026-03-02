#!/usr/bin/env python3
"""Enrich and prioritise vulnerabilities using CISA KEV and EPSS.

Usage:
    python3 vuln_prioritise.py --results-file scan-results.json     # Enrich scan results
    python3 vuln_prioritise.py --cve CVE-2024-1234                  # Single CVE lookup
    python3 vuln_prioritise.py --results-file scan-results.json --output prioritised.json

Sources:
    - CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    - EPSS: https://api.first.org/data/v1/epss
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# Cache KEV data in memory (downloaded once per run)
_kev_cache = None


def fetch_kev():
    """Download CISA Known Exploited Vulnerabilities catalog."""
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache

    try:
        req = Request(CISA_KEV_URL)
        req.add_header("User-Agent", "E8CR-VMPM-Bot/1.0")
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            # Build lookup by CVE ID
            _kev_cache = {}
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID")
                if cve_id:
                    _kev_cache[cve_id] = {
                        "vendor": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "name": vuln.get("vulnerabilityName"),
                        "date_added": vuln.get("dateAdded"),
                        "due_date": vuln.get("dueDate"),
                        "action": vuln.get("requiredAction"),
                    }
            return _kev_cache
    except Exception as e:
        print(f"WARNING: Could not fetch CISA KEV: {e}", file=sys.stderr)
        _kev_cache = {}
        return _kev_cache


def fetch_epss(cve_ids):
    """Fetch EPSS scores for a list of CVEs."""
    if not cve_ids:
        return {}

    results = {}
    # EPSS API accepts comma-separated CVEs, max ~100 at a time
    batch_size = 100
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        cve_param = ",".join(batch)
        url = f"{EPSS_API_URL}?cve={cve_param}"
        try:
            req = Request(url)
            req.add_header("User-Agent", "E8CR-VMPM-Bot/1.0")
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                for item in data.get("data", []):
                    cve_id = item.get("cve")
                    results[cve_id] = {
                        "epss": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0)),
                    }
        except Exception as e:
            print(f"WARNING: EPSS lookup failed for batch: {e}", file=sys.stderr)

    return results


def calculate_priority(severity, in_kev, epss_score, is_internet_facing=False):
    """Calculate priority score (0-100) combining multiple signals.

    Factors:
    - CVSS severity (base risk)
    - CISA KEV (actively exploited = critical urgency)
    - EPSS (probability of exploitation)
    - Internet-facing (higher exposure)
    """
    score = 0

    # Base score from CVSS (0-40 points)
    score += min(severity / 10 * 40, 40)

    # KEV bonus (0 or 30 points) — actively exploited is a huge signal
    if in_kev:
        score += 30

    # EPSS bonus (0-20 points)
    if epss_score:
        score += epss_score * 20

    # Internet-facing bonus (0 or 10 points)
    if is_internet_facing:
        score += 10

    return min(round(score, 1), 100)


def priority_label(score):
    if score >= 80:
        return "P1-CRITICAL"
    elif score >= 60:
        return "P2-HIGH"
    elif score >= 40:
        return "P3-MEDIUM"
    elif score >= 20:
        return "P4-LOW"
    return "P5-INFO"


def ml2_sla(priority, is_internet_facing=False):
    """Return ML2 patching SLA based on priority."""
    if priority.startswith("P1"):
        return "48 hours"
    elif priority.startswith("P2"):
        if is_internet_facing:
            return "48 hours"
        return "2 weeks"
    else:
        return "1 month"


def enrich_results(results_file, output=None):
    """Enrich scan results with KEV + EPSS data."""
    with open(results_file) as f:
        data = json.load(f)

    results = data.get("results", data) if isinstance(data, dict) else data
    if isinstance(results, dict) and "results" in results:
        results = results["results"]

    # Collect all CVEs
    all_cves = set()
    for r in results:
        for cve in r.get("cves", []):
            all_cves.add(cve)

    print(f"Enriching {len(results)} findings with {len(all_cves)} unique CVEs...",
          file=sys.stderr)

    # Fetch enrichment data
    kev = fetch_kev()
    epss = fetch_epss(list(all_cves))

    kev_hits = 0
    enriched = []

    for r in results:
        cves = r.get("cves", [])
        in_kev = any(cve in kev for cve in cves)
        if in_kev:
            kev_hits += 1

        # Get best EPSS score among CVEs
        best_epss = 0
        for cve in cves:
            if cve in epss:
                best_epss = max(best_epss, epss[cve]["epss"])

        severity = r.get("severity", 0)
        priority_score = calculate_priority(severity, in_kev, best_epss)
        priority = priority_label(priority_score)

        enriched_result = {
            **r,
            "priority_score": priority_score,
            "priority": priority,
            "ml2_sla": ml2_sla(priority),
            "in_cisa_kev": in_kev,
            "epss_score": best_epss,
            "epss_percentile": max(
                (epss.get(cve, {}).get("percentile", 0) for cve in cves),
                default=0
            ),
        }

        if in_kev:
            # Add KEV details for the first matching CVE
            for cve in cves:
                if cve in kev:
                    enriched_result["kev_details"] = kev[cve]
                    break

        enriched.append(enriched_result)

    # Sort by priority score descending
    enriched.sort(key=lambda x: x["priority_score"], reverse=True)

    output_data = {
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(enriched),
        "kev_matches": kev_hits,
        "priority_breakdown": {
            "P1-CRITICAL": sum(1 for r in enriched if r["priority"] == "P1-CRITICAL"),
            "P2-HIGH": sum(1 for r in enriched if r["priority"] == "P2-HIGH"),
            "P3-MEDIUM": sum(1 for r in enriched if r["priority"] == "P3-MEDIUM"),
            "P4-LOW": sum(1 for r in enriched if r["priority"] == "P4-LOW"),
            "P5-INFO": sum(1 for r in enriched if r["priority"] == "P5-INFO"),
        },
        "results": enriched,
    }

    if output:
        with open(output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"Wrote prioritised results to {output}")
    else:
        print(json.dumps(output_data, indent=2))

    return output_data


def lookup_cve(cve_id):
    """Look up a single CVE against KEV + EPSS."""
    kev = fetch_kev()
    epss = fetch_epss([cve_id])

    result = {
        "cve": cve_id,
        "in_cisa_kev": cve_id in kev,
        "epss": epss.get(cve_id, {}),
    }
    if cve_id in kev:
        result["kev_details"] = kev[cve_id]

    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Vulnerability prioritisation")
    parser.add_argument("--results-file", help="Greenbone scan results JSON")
    parser.add_argument("--cve", help="Single CVE lookup")
    parser.add_argument("--output", help="Output file")
    args = parser.parse_args()

    if args.cve:
        lookup_cve(args.cve)
    elif args.results_file:
        enrich_results(args.results_file, args.output)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
