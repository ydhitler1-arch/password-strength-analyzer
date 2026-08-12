"""
analyzer.py
------------
Core password strength analysis engine for the Password Strength Analyzer &
Security Awareness Tool.

Design notes
------------
* This module is the single source of truth for scoring logic. Both the
  Flask web app (app.py) and the command-line tool (cli.py) import and call
  `analyze_password()` — the UI is just a presentation layer on top of it.
* Passwords are analyzed in memory only. Nothing here writes a password to
  disk, a log file, or a database. That is a deliberate security-awareness
  choice, not an oversight — see README.md "Privacy & Security Notes".
"""

import math
import re
import os
from datetime import datetime

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_COMMON_PASSWORDS_FILE = os.path.join(_DATA_DIR, "common_passwords.txt")


def _load_common_passwords() -> set:
    """Load the bundled common-password wordlist into a lowercase set."""
    try:
        with open(_COMMON_PASSWORDS_FILE, "r", encoding="utf-8", errors="ignore") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


COMMON_PASSWORDS = _load_common_passwords()

# Common keyboard-walk sequences (QWERTY rows/columns, both directions checked)
KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "`1234567890-=",
]

LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a", "$": "s",
    "!": "i", "+": "t",
})

CURRENT_YEAR = datetime.now().year


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _character_pools(password: str) -> dict:
    return {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"[0-9]", password)),
        "symbols": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }


def _pool_size(pools: dict) -> int:
    size = 0
    if pools["lowercase"]:
        size += 26
    if pools["uppercase"]:
        size += 26
    if pools["digits"]:
        size += 10
    if pools["symbols"]:
        size += 32  # approx. printable ASCII symbols
    return size or 1


def _calculate_entropy(password: str, pools: dict) -> float:
    """Bits of entropy assuming a brute-force search of the character pool
    actually used. This is the standard NIST-style estimate — it does NOT
    account for dictionary-based cracking, which is handled separately by
    the common-password and pattern checks below."""
    pool = _pool_size(pools)
    if not password:
        return 0.0
    return round(len(password) * math.log2(pool), 1)


def _has_sequential_chars(password: str, run_length: int = 4) -> bool:
    """Detects ascending/descending runs like 'abcd' or '4321'."""
    lower = password.lower()
    for i in range(len(lower) - run_length + 1):
        chunk = lower[i:i + run_length]
        codes = [ord(c) for c in chunk]
        ascending = all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1))
        descending = all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1))
        if ascending or descending:
            return True
    return False


def _has_repeated_chars(password: str, run_length: int = 3) -> bool:
    """Detects runs like 'aaa' or '111'."""
    for i in range(len(password) - run_length + 1):
        if len(set(password[i:i + run_length])) == 1:
            return True
    return False


def _has_keyboard_walk(password: str, run_length: int = 4) -> bool:
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            chunk = row[i:i + run_length]
            if chunk in lower or chunk[::-1] in lower:
                return True
    return False


def _has_year_pattern(password: str) -> bool:
    return bool(re.search(r"(19|20)\d{2}", password))


def _matches_common_password(password: str) -> bool:
    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        return True
    # Normalize simple leetspeak substitutions and check again
    normalized = lower.translate(LEET_MAP)
    if normalized in COMMON_PASSWORDS:
        return True
    # Strip trailing digits (e.g. "password123" -> "password")
    stripped = re.sub(r"\d+$", "", lower)
    return stripped in COMMON_PASSWORDS and len(stripped) >= 4


def _estimate_crack_times(entropy_bits: float) -> dict:
    """Rough, order-of-magnitude crack-time estimates under a few common
    attack scenarios. These are illustrative, not precise — real crack
    speed depends heavily on the hashing algorithm the target system uses."""
    guesses = 2 ** entropy_bits
    scenarios = {
        "Online, throttled (100 guesses/hr)": 100 / 3600,
        "Online, unthrottled (10 guesses/sec)": 10,
        "Offline, slow hash (10k guesses/sec, e.g. bcrypt)": 1e4,
        "Offline, fast hash / GPU (10B guesses/sec, e.g. MD5/SHA1)": 1e10,
    }
    results = {}
    for label, rate in scenarios.items():
        seconds = guesses / rate / 2  # average case = half the keyspace
        results[label] = _humanize_seconds(seconds)
    return results


def _humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("century", 60 * 60 * 24 * 365 * 100),
        ("year", 60 * 60 * 24 * 365),
        ("day", 60 * 60 * 24),
        ("hour", 60 * 60),
        ("minute", 60),
        ("second", 1),
    ]
    plurals = {"century": "centuries"}
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            unit_label = plurals.get(name, name + "s")
            if value > 1_000_000:
                return f"{value:.0e} {unit_label}"
            return f"{value:,.1f} {unit_label}"
    return "instantly"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def _label_for_score(score: float, password: str) -> str:
    if not password:
        return "No password entered"
    elif score >= 85:
        return "Very Strong"
    elif score >= 65:
        return "Strong"
    elif score >= 45:
        return "Fair"
    elif score >= 25:
        return "Weak"
    else:
        return "Very Weak"


def analyze_password(password: str, live_breach_result: dict = None) -> dict:
    """Run the full analysis pipeline on a password and return a structured
    result dict. Never logs, stores, or echoes the raw password anywhere
    outside this return value.

    live_breach_result: optional dict from hibp_checker.check_pwned_password(),
    already fetched by the caller. If it confirms a breach, the score/label/
    recommendations are adjusted even when the local wordlist missed it."""

    if password is None:
        password = ""

    pools = _character_pools(password)
    variety_count = sum(pools.values())
    entropy = _calculate_entropy(password, pools)

    is_common = _matches_common_password(password)
    has_sequential = _has_sequential_chars(password)
    has_repeated = _has_repeated_chars(password)
    has_keyboard_walk = _has_keyboard_walk(password)
    has_year = _has_year_pattern(password)

    checks = {
        "length_ok": len(password) >= 8,
        "length_strong": len(password) >= 12,
        "has_lowercase": pools["lowercase"],
        "has_uppercase": pools["uppercase"],
        "has_digits": pools["digits"],
        "has_symbols": pools["symbols"],
        "not_common_password": not is_common,
        "no_sequential_pattern": not has_sequential,
        "no_repeated_pattern": not has_repeated,
        "no_keyboard_walk": not has_keyboard_walk,
    }

    # --- Scoring (0-100) -----------------------------------------------
    score = 0
    if password:
        score += min(len(password), 20) * 2.5      # up to 50 pts for length
        score += variety_count * 7.5                # up to 30 pts for variety
        score += 20 if checks["length_strong"] else 0
        score = min(score, 100)

        # Heavy penalties for real-world weaknesses entropy alone won't catch
        if is_common:
            score = min(score, 15)
        if has_sequential or has_repeated or has_keyboard_walk:
            score = max(0, score - 25)
        if has_year and len(password) <= 10:
            score = max(0, score - 5)

    score = round(max(0, min(100, score)))

    label = _label_for_score(score, password)

    # --- Recommendations -------------------------------------------------
    recommendations = []
    if password:
        if not checks["length_strong"]:
            recommendations.append("Use at least 12 characters — longer passwords are exponentially harder to brute-force.")
        if not pools["uppercase"]:
            recommendations.append("Add at least one uppercase letter.")
        if not pools["lowercase"]:
            recommendations.append("Add at least one lowercase letter.")
        if not pools["digits"]:
            recommendations.append("Add at least one number.")
        if not pools["symbols"]:
            recommendations.append("Add at least one symbol (e.g. ! @ # $ %).")
        if is_common:
            recommendations.append("This password (or a close variant) appears on public breach/common-password lists — do not use it anywhere.")
        if has_sequential:
            recommendations.append("Avoid sequential runs like 'abcd' or '4321'.")
        if has_repeated:
            recommendations.append("Avoid repeated characters like 'aaa' or '111'.")
        if has_keyboard_walk:
            recommendations.append("Avoid keyboard walks like 'qwerty' or 'asdf'.")
        if has_year:
            recommendations.append("Avoid embedding years or dates — they're commonly guessed.")
        if not recommendations:
            recommendations.append("Solid password. Consider a password manager so you never have to reuse or remember it.")
    else:
        recommendations.append("Enter a password to see a live analysis.")

    breach_check = {"checked": False, "breached": False, "count": 0, "error": None}
    if live_breach_result:
        breach_check = live_breach_result
        if live_breach_result.get("checked") and live_breach_result.get("breached"):
            is_common = True
            checks["not_common_password"] = False
            score = min(score, 15)
            label = _label_for_score(score, password)
            count = live_breach_result.get("count", 0)
            recommendations.insert(
                0,
                f"This password was found in {count:,} known breaches (Have I Been Pwned live check) — change it immediately anywhere it's used.",
            )

    return {
        "score": score,
        "label": label,
        "length": len(password),
        "entropy_bits": entropy,
        "character_pools": pools,
        "variety_count": variety_count,
        "checks": checks,
        "is_common_password": is_common,
        "breach_check": breach_check,
        "patterns_detected": {
            "sequential": has_sequential,
            "repeated": has_repeated,
            "keyboard_walk": has_keyboard_walk,
            "year_or_date": has_year,
        },
        "crack_time_estimates": _estimate_crack_times(entropy) if password else {},
        "recommendations": recommendations,
    }


# General, password-independent security awareness content shown in the UI
# and included in every generated report.
SECURITY_AWARENESS_TIPS = [
    "Use a unique password for every account — one breach shouldn't compromise the rest.",
    "Use a password manager (Bitwarden, 1Password, KeePassXC) to generate and store strong, unique passwords.",
    "Turn on multi-factor authentication (MFA) wherever it's offered — it stops most account takeovers even if your password leaks.",
    "Prefer a long passphrase (e.g. four random words) over a short complex string — it's easier to remember and harder to crack.",
    "Never reuse your email account's password anywhere else — it's usually the master key to resetting everything else.",
    "Be wary of phishing: a legitimate site will never email you asking you to 'confirm' your password.",
    "Check haveibeenpwned.com periodically to see if any of your accounts appear in a known breach.",
    "Change a password immediately if a service you use discloses a breach — don't wait.",
]

if __name__ == "__main__":
    import json
    import sys
    pw = sys.argv[1] if len(sys.argv) > 1 else "Password123"
    print(json.dumps(analyze_password(pw), indent=2))
