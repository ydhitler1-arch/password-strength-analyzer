"""
generator.py
------------
Cryptographically secure password and passphrase generator.

Everything here uses the `secrets` module (OS CSPRNG), never `random`.

Two modes
---------
* Random password   -- characters drawn uniformly from the selected pools,
                       with at least one character from every selected pool.
* Passphrase        -- diceware-style: N words drawn uniformly from a
                       2048-word list (11 bits per word), optionally with
                       capitalization and a random digit appended.

Each result carries `generator_entropy_bits`: the *true* entropy of the
generation process (what an attacker who knows exactly how it was made
must search), which is the honest number for generated secrets. The
analyzer's pool-based estimate is still applied on top, so the strength
meter can be run on the output like any other password.
"""

import math
import os
import secrets

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_WORDLIST_FILE = os.path.join(_DATA_DIR, "wordlist.txt")

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = set("Il1O0o|`'\"")

MIN_LENGTH, MAX_LENGTH = 8, 128
MIN_WORDS, MAX_WORDS = 3, 12
SEPARATORS = {"-", ".", "_", " ", ""}


def _load_wordlist() -> list:
    try:
        with open(_WORDLIST_FILE, "r", encoding="utf-8") as f:
            return [w.strip() for w in f if w.strip()]
    except OSError:
        return []


WORDLIST = _load_wordlist()


def generate_password(length: int = 16, lowercase: bool = True, uppercase: bool = True,
                      digits: bool = True, symbols: bool = True,
                      avoid_ambiguous: bool = False) -> dict:
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")

    pools = []
    for enabled, chars in ((lowercase, LOWER), (uppercase, UPPER),
                           (digits, DIGITS), (symbols, SYMBOLS)):
        if enabled:
            if avoid_ambiguous:
                chars = "".join(c for c in chars if c not in AMBIGUOUS)
            pools.append(chars)
    if not pools:
        raise ValueError("select at least one character type")

    # One guaranteed character per pool, the rest from the combined pool,
    # then a CSPRNG shuffle so the guaranteed ones aren't in fixed positions.
    combined = "".join(pools)
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(combined) for _ in range(length - len(pools))]
    secrets.SystemRandom().shuffle(chars)

    return {
        "mode": "password",
        "value": "".join(chars),
        # Upper-bound-style estimate: the "at least one of each" rule removes
        # a small fraction of the space, so this slightly overstates it.
        "generator_entropy_bits": round(length * math.log2(len(combined)), 1),
    }


def generate_passphrase(words: int = 5, separator: str = "-",
                        capitalize: bool = False, add_number: bool = False) -> dict:
    if not WORDLIST:
        raise RuntimeError("wordlist is unavailable (data/wordlist.txt)")
    if not MIN_WORDS <= words <= MAX_WORDS:
        raise ValueError(f"words must be between {MIN_WORDS} and {MAX_WORDS}")
    if separator not in SEPARATORS:
        raise ValueError("separator must be one of: - . _ space, or empty")

    picked = [secrets.choice(WORDLIST) for _ in range(words)]
    entropy = words * math.log2(len(WORDLIST))
    if capitalize:
        picked = [w.capitalize() for w in picked]
    value = separator.join(picked)
    if add_number:
        value += secrets.choice(DIGITS)
        entropy += math.log2(len(DIGITS))

    return {
        "mode": "passphrase",
        "value": value,
        "generator_entropy_bits": round(entropy, 1),
    }
