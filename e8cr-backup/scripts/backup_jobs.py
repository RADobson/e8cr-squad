#!/usr/bin/env python3
"""Backup job audit utility (MVP stub with real JSON I/O shape)."""

import argparse
import json
from datetime import datetime

from adapters import (
    veeam_fetch_jobs_sample,
    azure_fetch_jobs_sample,
    normalize_jobs,
)


def get_jobs(provider: str):
    if provider == "veeam":
        return normalize_jobs(veeam_fetch_jobs_sample())
    if provider == "azure":
        return normalize_jobs(azure_fetch_jobs_sample())
    veeam = normalize_jobs(veeam_fetch_jobs_sample())
    azure = normalize_jobs(azure_fetch_jobs_sample())
    return veeam + azure


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["audit", "summary"], default="audit")
    p.add_argument("--provider", choices=["all", "veeam", "azure"], default="all")
    args = p.parse_args()

    jobs = get_jobs(args.provider)
    if args.mode == "summary":
        out = {
            "total": len(jobs),
            "success": len([j for j in jobs if j["status"] == "success"]),
            "failed": len([j for j in jobs if j["status"] == "failed"]),
            "missed": len([j for j in jobs if j["status"] == "missed"]),
            "generatedAt": datetime.now().isoformat() + "Z",
        }
    else:
        out = {"generatedAt": datetime.now().isoformat() + "Z", "jobs": jobs}

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
