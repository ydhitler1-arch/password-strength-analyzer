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
MIN_EASY_SCORE = 65

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



# --- "easy to remember" builders ------------------------------------------
# Readable combinations of the user's own details (Dev@13crik#06). They are
# quick to remember but guessable by someone who knows the details, so the
# only entropy credited is the separators (and any stand-in word/digits used
# when the user left a field empty).

EASY_SYMBOLS = "@#$%&*!._-"


def _parts(profile, words):
    """Split the profile into reusable fragments, with stand-ins (counted as
    random bits) for anything the user didn't give."""
    name_tokens = _tokens(profile.get("name"))
    fav_tokens = _tokens(profile.get("favorites"))
    name = name_tokens[0] if name_tokens else None
    dob = _dob_digits(profile.get("dob"))
    return name, _shuffled(fav_tokens), dob


def _sym():
    return secrets.choice(EASY_SYMBOLS)


def _easy_ctx(profile, words):
    name, favs, dob = _parts(profile, words)
    bits = 0.0
    if name is None:
        name = secrets.choice(generator.WORDLIST)
        bits += math.log2(len(generator.WORDLIST))
    def fav(i):
        nonlocal bits
        if favs:
            return favs[i % len(favs)]
        bits += math.log2(len(generator.WORDLIST))
        return secrets.choice(generator.WORDLIST)
    def digits(kind):
        """kind: 'day', 'month', 'yy', 'dm' (day+month), 'my' (month+yy)"""
        nonlocal bits
        if dob:
            d, m, y = dob
            return {"day": d, "month": m, "yy": y[-2:], "dm": d + m, "my": m + y[-2:]}[kind]
        n = 4 if kind in ("dm", "my") else 2
        bits += _bits(generator.DIGITS, n)
        return _rand_str(generator.DIGITS, n)
    return name, fav, digits, lambda: bits


def _easy_short(words, profile):
    """Dev@13crik#06  -- name start, day, favourite start, year."""
    name, fav, digits, getbits = _easy_ctx(profile, words)
    s1, s2 = _sym(), _sym()
    value = f"{name[:3].capitalize()}{s1}{digits('day')}{fav(0)[:4].lower()}{s2}{digits('yy')}"
    return value, getbits() + 2 * math.log2(len(EASY_SYMBOLS))


def _easy_reverse(words, profile):
    """cricket.dev#06  -- favourite, name start, year."""
    name, fav, digits, getbits = _easy_ctx(profile, words)
    s1, s2 = _sym(), _sym()
    value = f"{fav(1).lower()}{s1}{name[:3].lower()}{s2}{digits('yy')}"
    return value, getbits() + 2 * math.log2(len(EASY_SYMBOLS))


def _easy_full(words, profile):
    """Devan@Cricket#1305  -- full name, full favourite, day+month."""
    name, fav, digits, getbits = _easy_ctx(profile, words)
    s1, s2 = _sym(), _sym()
    value = f"{name.capitalize()}{s1}{fav(2).capitalize()}{s2}{digits('dm')}"
    return value, getbits() + 2 * math.log2(len(EASY_SYMBOLS))


def _easy_flip(words, profile):
    """cricket_Devan$0506  -- favourite, full name, month+year."""
    name, fav, digits, getbits = _easy_ctx(profile, words)
    s1, s2 = _sym(), _sym()
    value = f"{fav(3).lower()}{s1}{name.capitalize()}{s2}{digits('my')}"
    return value, getbits() + 2 * math.log2(len(EASY_SYMBOLS))


def _easy_upgrade(base: str):
    """Your own word, kept readable: Rahul-Tiger-Blue@47"""
    core = (re.sub(r"[^A-Za-z]", "", base)[:10] or "Pass").capitalize()
    w1 = secrets.choice(generator.WORDLIST).capitalize()
    w2 = secrets.choice(generator.WORDLIST).capitalize()
    sep, sym = secrets.choice("-._"), _sym()
    digits = _rand_str(generator.DIGITS, 2)
    return f"{core}{sep}{w1}{sep}{w2}{sym}{digits}", \
        2 * math.log2(len(generator.WORDLIST)) + math.log2(3) + math.log2(len(EASY_SYMBOLS)) + _bits(generator.DIGITS, 2)


EASY_PATTERNS = [
    ("Short & familiar", "Start of your name, birth day, start of a favourite, then the year. Quick to type and remember.", _easy_short),
    ("Favourite first", "A favourite thing, the start of your name, then the year.", _easy_reverse),
    ("Name + favourite", "Your name and a favourite thing in full, joined by symbols, with your birth day and month.", _easy_full),
    ("Favourite + name", "A favourite thing, your name, then birth month and year.", _easy_flip),
]

EASY_NOTE = "Easy to remember, but easier to guess for someone who knows your details."

STRONG_PATTERNS = [
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


def _build(name, why, fn, args, tier="strong"):
    """Retry until the analyzer is happy: no common/sequential/repeated/
    keyboard-walk patterns and a good score. Strong-tier results must also
    be free of year/date patterns and score high; easy-tier results (which
    deliberately contain readable personal fragments) need a decent score."""
    easy = tier == "easy"
    min_score = MIN_EASY_SCORE if easy else MIN_ACCEPT_SCORE
    for _ in range(40):
        value, bits = fn(*args)
        result = analyzer.analyze_password(value)
        c, pat = result["checks"], result["patterns_detected"]
        if (result["score"] >= min_score and c["not_common_password"]
                and c["no_sequential_pattern"] and c["no_repeated_pattern"]
                and c["no_keyboard_walk"] and (easy or not pat["year_or_date"])):
            return {
                "pattern": name,
                "tier": tier,
                "description": why,
                "value": value,
                "random_entropy_bits": round(bits, 1),
                "targeted_strength": EASY_NOTE if easy else _strength_label(bits),
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

    easy, strong = [], []
    if words or profile["dob"]:
        for name, why, fn in EASY_PATTERNS:
            built = _build(name, why, fn, (words, profile), tier="easy")
            if built:
                easy.append(built)
    if words:
        for name, why, fn, _ in STRONG_PATTERNS:
            built = _build(name, why, fn, (words, profile))
            if built:
                strong.append(built)
    if base_password:
        built = _build("Your password, kept readable",
                       "Keeps your current word and adds two random words, a symbol and two digits.",
                       lambda: _easy_upgrade(base_password), (), tier="easy")
        if built:
            easy.insert(0, built)
        built = _build("Upgrade of your password (extra strong)",
                       "Keeps the letters of your current password as a recognisable core, then adds random characters around it.",
                       lambda: _upgrade_base(base_password), ())
        if built:
            strong.insert(0, built)
    suggestions = easy + strong
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
        "note": ("Easy-to-remember options are built from your own details, so someone who knows you could guess "
                 "them -- avoid them for important accounts. The extra-strong options get their strength from "
                 "random characters, scored on that random part alone."),
    }
