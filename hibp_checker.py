"""
hibp_checker.py
---------------
Live breach check against the Have I Been Pwned "Pwned Passwords" API,
using the k-anonymity range search: only the first 5 hex characters of
the password's SHA-1 hash are ever sent over the network. The password
itself, and even its full hash, never leave this machine.

API contract (verified against the live API):
  GET https://api.pwnedpasswords.com/range/{5-hex-prefix}
  -> newline-separated "SUFFIX:COUNT" lines for every hash sharing that
     prefix (typically several hundred). No API key required, no hard
     rate limit, and the endpoint always returns HTTP 200.

This is used by:
  - cli.py, via the --live flag (this machine has no browser)
  - app.py's /api/analyze and /api/report, if a caller opts in with
    {"live_check": true} (mainly useful for testing / non-browser clients)
  - the browser UI does its OWN equivalent check directly against HIBP
    using the Web Crypto API, without a round trip through this Flask
    app at all -- see the comment in templates/index.html.
"""

import hashlib
import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_TIMEOUT = 5


def check_pwned_password(password: str) -> dict:
    """Check a password against the live HIBP breach corpus.

    Returns a dict: {checked, breached, count, error}. Never raises --
    any network problem is reported via 'error' so callers can fall back
    to the bundled local wordlist instead."""
    if not password:
        return {"checked": False, "breached": False, "count": 0, "error": "empty password"}

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            headers={
                "User-Agent": "CipherCheck-Password-Analyzer",
                "Add-Padding": "true",  # asks HIBP to pad the response size against traffic analysis
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return {"checked": False, "breached": False, "count": 0, "error": str(exc)}

    for line in resp.text.splitlines():
        if ":" not in line:
            continue
        line_suffix, count_str = line.split(":", 1)
        if line_suffix.strip() == suffix:
            try:
                count = int(count_str.strip())
            except ValueError:
                count = 0
            return {"checked": True, "breached": True, "count": count, "error": None}

    return {"checked": True, "breached": False, "count": 0, "error": None}


if __name__ == "__main__":
    import sys
    pw = sys.argv[1] if len(sys.argv) > 1 else "password"
    print(check_pwned_password(pw))
