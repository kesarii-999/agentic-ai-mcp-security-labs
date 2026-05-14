"""
Minimal JSON HTTP POST helper (stdlib only).
Prints response body on HTTP errors to aid local debugging.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from typing import Any


def post_json(
    url: str,
    payload: dict[str, Any],
    timeout: float = 60.0,
    extra_headers: dict[str, str] | None = None,
    tolerate_http_status: set[int] | None = None,
) -> dict[str, Any]:
    """
    POST JSON to url; parse JSON response.
    On HTTP errors, prints a helpful message including response body (truncated).

    If tolerate_http_status is set and the response code is in it, returns parsed JSON
    (or empty dict) instead of raising — useful for expected 403/400 API flows.
    """
    data = json.dumps(payload).encode("utf-8")
    hdrs: dict[str, str] = {"Content-Type": "application/json; charset=utf-8"}
    if extra_headers:
        hdrs.update(extra_headers)
    req = urllib.request.Request(url, data=data, method="POST", headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            if not raw.strip():
                return {}
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        print(f"[HTTP {e.code}] {e.reason} for {url}", file=sys.stderr)
        if body:
            lim = 4000
            snippet = body if len(body) <= lim else body[:lim] + "…(truncated)"
            print(f"Response body:\n{snippet}", file=sys.stderr)
        if tolerate_http_status is not None and e.code in tolerate_http_status:
            if not body.strip():
                return {}
            try:
                val = json.loads(body)
                return val if isinstance(val, dict) else {"_non_object_json": True, "value": val}
            except json.JSONDecodeError:
                return {"_invalid_json_body": True}
        raise
    except urllib.error.URLError as e:
        print(f"[URL ERROR] {e.reason} for {url}", file=sys.stderr)
        raise
