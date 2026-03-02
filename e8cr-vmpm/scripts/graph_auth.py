#!/usr/bin/env python3
"""Microsoft Graph authentication using client credentials flow.

Requires: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars.
Returns an access token for Microsoft Graph API calls.

Usage:
    python3 graph_auth.py                # Print token to stdout
    python3 graph_auth.py --check        # Verify auth works
"""

import os
import sys
import json
import argparse
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def get_env():
    tenant = os.environ.get("AZURE_TENANT_ID")
    client_id = os.environ.get("AZURE_CLIENT_ID")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")
    missing = []
    if not tenant:
        missing.append("AZURE_TENANT_ID")
    if not client_id:
        missing.append("AZURE_CLIENT_ID")
    if not client_secret:
        missing.append("AZURE_CLIENT_SECRET")
    if missing:
        print(f"ERROR: Missing environment variables: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)
    return tenant, client_id, client_secret


def get_token(tenant, client_id, client_secret):
    """Acquire access token via client credentials flow."""
    url = TOKEN_URL.format(tenant=tenant)
    data = urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }).encode()
    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urlopen(req) as resp:
            body = json.loads(resp.read())
            return body["access_token"]
    except HTTPError as e:
        err = e.read().decode()
        print(f"ERROR: Auth failed ({e.code}): {err}", file=sys.stderr)
        sys.exit(1)


def check_auth(token):
    """Verify token works by hitting /organization endpoint."""
    req = Request(f"{GRAPH_BASE}/organization", method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(req) as resp:
            body = json.loads(resp.read())
            orgs = body.get("value", [])
            if orgs:
                name = orgs[0].get("displayName", "Unknown")
                tenant_id = orgs[0].get("id", "Unknown")
                print(f"OK: Authenticated to tenant '{name}' ({tenant_id})")
            else:
                print("OK: Authenticated (no org info returned)")
            return True
    except HTTPError as e:
        err = e.read().decode()
        print(f"ERROR: Auth check failed ({e.code}): {err}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Microsoft Graph authentication")
    parser.add_argument("--check", action="store_true", help="Verify auth works")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)

    if args.check:
        if not check_auth(token):
            sys.exit(1)
    else:
        print(token)


if __name__ == "__main__":
    main()
