#!/usr/bin/env python3
"""Shared Microsoft Graph helpers for E8CR bots.

Provides:
- retry/backoff for transient failures
- paginated GET collection fetch
- optional incremental filter helper for lastModifiedDateTime
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


TRANSIENT_HTTP = {408, 425, 429, 500, 502, 503, 504}


def _http_get_json(url: str, token: str, timeout: int = 30) -> Dict[str, Any]:
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def graph_get_json(
    url: str,
    token: str,
    timeout: int = 30,
    retries: int = 4,
    backoff_seconds: float = 0.8,
) -> Dict[str, Any]:
    """GET one Graph payload with retry/backoff on transient failures."""
    last_err: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            return _http_get_json(url, token=token, timeout=timeout)
        except HTTPError as e:
            last_err = e
            if e.code not in TRANSIENT_HTTP or attempt == retries:
                raise
            retry_after = e.headers.get("Retry-After") if hasattr(e, "headers") else None
            if retry_after and str(retry_after).isdigit():
                time.sleep(float(retry_after))
            else:
                time.sleep(backoff_seconds * (2**attempt))
        except URLError as e:
            last_err = e
            if attempt == retries:
                raise
            time.sleep(backoff_seconds * (2**attempt))
    if last_err:
        raise last_err
    raise RuntimeError("graph_get_json failed without explicit exception")


def graph_get_paginated(
    first_url: str,
    token: str,
    timeout: int = 30,
    retries: int = 4,
) -> List[Dict[str, Any]]:
    """Follow @odata.nextLink and return merged items from value arrays."""
    items: List[Dict[str, Any]] = []
    url: Optional[str] = first_url
    while url:
        body = graph_get_json(url, token=token, timeout=timeout, retries=retries)
        value = body.get("value", [])
        if isinstance(value, list):
            items.extend(value)
        url = body.get("@odata.nextLink")
    return items


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_modified_since_filter(
    since_iso: Optional[str],
    field: str = "lastModifiedDateTime",
) -> Optional[str]:
    """Create OData filter for modified-since queries when endpoint supports it."""
    if not since_iso:
        return None
    # Graph expects quoted datetime string.
    return f"{field} ge {since_iso}"


def with_query(base_url: str, params: Dict[str, Any]) -> str:
    usable = {k: v for k, v in params.items() if v is not None and v != ""}
    if not usable:
        return base_url
    return f"{base_url}{'&' if '?' in base_url else '?'}{urlencode(usable)}"
