"""
personalized.py
---------------
Suggests several differently-shaped passwords built from details the user
gives (name, date of birth, favourite things) and/or from a weak password
they already have, and runs every suggestion through analyzer.py.

Security model -- why personal details are only a *memory anchor*
-----------------------------------------------------------------
Anything derived from personal details can be guessed by someone who knows
(or can look up) those details. So each suggestion mixes personal fragments
with CSPRNG-generated material, and the strength we report counts ONLY the
random part (`random_entropy_bits`) -- personal fragments are credited with
zero bits. That number is the honest estimate against a targeted attacker.

Nothing here is stored or logged; inputs live in memory for one request.
"""

import math
import re
import secrets

import analyzer
import generator

MAX_FIELD_LEN = 64
MAX_TOKENS = 20
MAX_TOKEN_LEN = 12
MIN_ACCEPT_SCORE = 75

LOWER_DIGITS = generator.LOWER + generator.DIGITS
FULL_POOL = generator.LOWER + generator.UPPER + generator.DIGITS + generator.SYMBOLS
# Symbols that are easy to type and accepted by nearly every site.
SAFE_SYMBOLS = "!@#$%^&*-_=+?"
LEET = {"a": "@", "e": "3", "i": "!", "o": "0", "s": "$", "t": "7"}


def _clean(value, limit=MAX_FIELD_LEN) -> str:
    return str(value or "").strip()[:limit]


def _tokens(*fields) -> list:
    """Split free text into alphanumeric words (names, favourites...)."""
    found, seen = [], set()
    for field in fields:
        for raw in re.split(r"[,\s;/]+", _clean(field, 256)):
            word = re.sub(r"[^A-Za-z0-9]", "", raw)[:MAX_TOKEN_LEN]
            if len(word) >= 2 and word.lower() not in seen:
                seen.add(word.lower())
                found.append(word)
    return found[:MAX_TOKENS]


def _dob_digits(dob: str):
    """Return (day, month, year) digit strings from common DOB formats, or None."""
    dob = re.sub(r"^\s*(\d{2})(\d{2})(\d{4})\s*$", r"\1/\2/\3", dob or "")  # 13052006 -> 13/05/2006
    m = re.fullmatch(r"\s*(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})\s*", dob)
    if m:
        y, mo, d = m.groups()
    else:
        m = re.fullmatch(r"\s*(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})\s*", dob or "")
        if not m:
            return None
        d, mo, y = m.groups()
    return d.zfill(2), mo.zfill(2), y


def _personal_words(profile: dict) -> list:
    return _tokens(profile.get("name"), profile.get("favorites"))


def _rand_str(pool: str, n: int) -> str:
    return "".join(secrets.choice(pool) for _ in range(n))


def _bits(pool: str, n: int) -> float:
    return n * math.log2(len(pool))


def _style(word: str) -> str:
    """Capitalise and leet-substitute a random subset of letters.
    The substitutions are NOT counted as entropy."""
    word = word.capitalize()
    out = []
    for i, ch in enumerate(word):
        if i > 0 and ch.lower() in LEET and secrets.randbelow(2):
            out.append(LEET[ch.lower()])
        else:
            out.append(ch)
    return "".join(out)


def _shuffled(items: list) -> list:
    items = list(items)
    secrets.SystemRandom().shuffle(items)
    return items


# --- pattern builders: each returns (value, random_bits) ------------------

def _anchor_block(words, profile):
    """Word + random block + word -- easiest to remember."""
    a, b = (_shuffled(words) + _shuffled(words))[:2]
    block = _rand_str(LOWER_DIGITS, 8)
    s1, s2 = secrets.choice(SAFE_SYMBOLS), secrets.choice(SAFE_SYMBOLS)
    return (f"{_style(a)}{s1}{block}{s2}{_style(b)}",
            _bits(LOWER_DIGITS, 8) + 2 * math.log2(len(SAFE_SYMBOLS)))


def _word_chain(words, profile):
    """One personal word + random dictionary words, passphrase style."""
    mine = secrets.choice(words)
    picks = [secrets.choice(generator.WORDLIST).capitalize() for _ in range(4)]
    parts = _shuffled([_style(mine)] + picks)
    sep = secrets.choice("-._")
    digits = _rand_str(generator.DIGITS, 2)
    sym = secrets.choice(SAFE_SYMBOLS)
    bits = 4 * math.log2(len(generator.WORDLIST)) + _bits(generator.DIGITS, 2) \
        + math.log2(len(SAFE_SYMBOLS)) + math.log2(3)
    return sep.join(parts) + digits + sym, bits


def _initials_mix(words, profile):
    """Initials of your details + a date anchor + a fully random tail."""
    initials = "".join(w[0].upper() if i % 2 == 0 else w[0].lower()
                       for i, w in enumerate(words[:4]))
    dob = _dob_digits(profile.get("dob"))
    anchor = (dob[0] + dob[1]) if dob else ""   # memory aid, 0 bits credited
    tail = _rand_str(FULL_POOL, 8)
    return f"{initials}{secrets.choice(SAFE_SYMBOLS)}{anchor}{tail}", \
        _bits(FULL_POOL, 8) + math.log2(len(SAFE_SYMBOLS))


def _upgrade_base(base: str):
    """Keep a recognisable core of the user's own password, harden around it."""
    core = re.sub(r"[^A-Za-z]", "", base)[:10] or "Pass"
    tail = _rand_str(FULL_POOL, 8)
    pre = _rand_str(LOWER_DIGITS, 2)
    return f"{pre}{_style(core)}{secrets.choice(SAFE_SYMBOLS)}{tail}", \
        _bits(FULL_POOL, 8) + _bits(LOWER_DIGITS, 2) + math.log2(len(SAFE_SYMBOLS))


def _fully_random(words, profile):
    """Fallback with no personal data at all."""
    out = generator.generate_password(16, avoid_ambiguous=True)
    return out["value"], out["generator_entropy_bits"]


PATTERNS = [
    ("Anchor + random block",
     "Two of your words wrapped around a random 8-character block. Easy to recall the words; the block carries the strength.",
     _anchor_block, True),
    ("Personal passphrase",
     "One of your words mixed with four random dictionary words, a separator, digits and a symbol. Long and memorable.",
     _word_chain, True),
    ("Initials + random tail",
     "Initials of your details, a date-based anchor if you gave a date of birth, then 8 fully random characters.",
     _initials_mix, True),
]


def _strength_label(bits: float) -> str:
    if bits >= 60:
        return "Very strong against a targeted attack"
    if bits >= 45:
        return "Strong against a targeted attack"
    return "Moderate against a targeted attack"


def _build(name, why, fn, args):
    """Retry until the analyzer is happy: no common/sequential/repeated/
    keyboard-walk/year patterns and a high score."""
    for _ in range(40):
        value, bits = fn(*args)
        result = analyzer.analyze_password(value)
        c, p = result["checks"], result["patterns_detected"]
        if (result["score"] >= MIN_ACCEPT_SCORE and c["not_common_password"]
                and c["no_sequential_pattern"] and c["no_repeated_pattern"]
                and c["no_keyboard_walk"] and not p["year_or_date"]):
            return {
                "pattern": name,
                "description": why,
                "value": value,
                "random_entropy_bits": round(bits, 1),
                "targeted_strength": _strength_label(bits),
                "analysis": result,
            }
    return None


def suggest(profile: dict, base_password: str = "") -> dict:
    """profile: {name, dob, favorites}. base_password: optional existing password."""
    profile = {
        "name": _clean(profile.get("name")),
        "dob": _clean(profile.get("dob"), 20),
        "favorites": _clean(profile.get("favorites"), 256),
    }
    base_password = (base_password or "")[:256]
    words = _personal_words(profile)

    warnings = []
    if base_password:
        low = base_password.lower()
        leaked = [w for w in words if len(w) >= 3 and w.lower() in low]
        if leaked:
            warnings.append("Your current password contains personal details you entered "
                            "(" + ", ".join(leaked) + ") -- that makes it easy to guess for anyone who knows you.")
        dob = _dob_digits(profile["dob"])
        if dob and (dob[2] in base_password or dob[0] + dob[1] in base_password):
            warnings.append("Your current password appears to contain your date of birth.")

    suggestions = []
    if words:
        for name, why, fn, _ in PATTERNS:
            built = _build(name, why, fn, (words, profile))
            if built:
                suggestions.append(built)
    if base_password:
        built = _build("Upgrade of your password",
                       "Keeps the letters of your current password as a recognisable core, then adds random characters around it.",
                       lambda: _upgrade_base(base_password), ())
        if built:
            suggestions.insert(0, built)
    if len(suggestions) < 2:
        built = _build("Fully random",
                       "Not enough personal details were usable, so here is a random password with no personal data.",
                       _fully_random, (words, profile))
        if built:
            suggestions.append(built)

    return {
        "suggestions": suggestions,
        "warnings": warnings,
        "used_details": len(words),
        "note": ("Personal details are only used as memory anchors. Strength is credited from the "
                 "random parts alone, so these hold up even if someone knows your details."),
    }
