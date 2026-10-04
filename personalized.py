"""
personalized.py
---------------
Suggests passwords built ONLY from what the user typed: their name, date of
birth, favourite things (and, when strengthening, their current password).
The only characters added are separator symbols. Nothing random is mixed in,
so every suggestion can be remembered from the details alone. Each result is
run through analyzer.py.

Trade-off, stated plainly: these are readable mixes of personal details, so
someone who knows those details could guess them. Use them for low-risk
accounts; use the random generator for important ones. Inputs live in memory
for one request and are never stored or logged.
"""

import re
import secrets

import analyzer

MAX_FIELD_LEN = 64
MAX_TOKENS = 20
MAX_TOKEN_LEN = 12
MIN_SCORE = 60
DEFAULT_COUNT = 2
MAX_COUNT = 4

SYMBOLS = "@#$%&*!._-"

NOTE = ("Built only from your own details, so they're easy to remember -- but someone who knows "
        "you could guess them. Avoid them for important accounts; use the random generator there.")
HINT = "Easy to remember, but easier to guess for someone who knows your details."


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
        m = re.fullmatch(r"\s*(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})\s*", dob)
        if not m:
            return None
        d, mo, y = m.groups()
    return d.zfill(2), mo.zfill(2), y


def _shuffled(items: list) -> list:
    items = list(items)
    secrets.SystemRandom().shuffle(items)
    return items


def _sym() -> str:
    return secrets.choice(SYMBOLS)


class _Frags:
    """The user's own pieces. Missing ones are simply None / empty."""

    def __init__(self, profile: dict, base_password: str = ""):
        names = _tokens(profile.get("name"))
        self.name = names[0] if names else None
        self.favs = _shuffled(_tokens(profile.get("favorites")))
        dob = _dob_digits(profile.get("dob"))
        self.day, self.month, self.year4 = dob if dob else (None, None, None)
        self.yy = self.year4[-2:] if dob else None
        letters = re.sub(r"[^A-Za-z]", "", base_password or "")[:10]
        self.core = letters if len(letters) >= 2 else None
        digit_runs = re.findall(r"\d+", base_password or "")
        self.base_digits = max(digit_runs, key=len)[:8] if digit_runs else None

    def has(self, need: str) -> bool:
        return {
            "name": self.name, "fav": self.favs, "fav2": len(self.favs) >= 2,
            "dob": self.day, "core": self.core,
        }[need] not in (None, [], False)


# Each builder returns a password made only from _Frags pieces plus symbols.
def _short(f):    return f"{f.name[:3].capitalize()}{_sym()}{f.day}{f.favs[0][:4].lower()}{_sym()}{f.yy}"
def _reverse(f):  return f"{f.favs[0].lower()}{_sym()}{f.name[:3].lower()}{_sym()}{f.yy}"
def _full(f):     return f"{f.name.capitalize()}{_sym()}{f.favs[0].capitalize()}{_sym()}{f.day}{f.month}"
def _flip(f):     return f"{f.favs[0].lower()}{_sym()}{f.name.capitalize()}{_sym()}{f.month}{f.yy}"
def _two_favs(f): return f"{f.favs[0].lower()}{_sym()}{f.favs[1].capitalize()}{_sym()}{f.day}{f.yy}"
def _year(f):     return f"{f.name.capitalize()}{_sym()}{f.year4}{_sym()}{f.day}"
def _name_fav(f): return f"{f.name.capitalize()}{_sym()}{f.favs[0].lower()}{_sym()}{f.name[:3].upper()}"
def _name_dob(f): return f"{f.name.capitalize()}{_sym()}{f.day}{f.month}{_sym()}{f.month}{f.yy}"


def _keep_yours(f):
    """Your own password's word and digits, tidied up and joined with symbols."""
    digits = None
    if f.base_digits:
        d = f.base_digits   # use the whole run or a slice of it, avoiding 3-in-a-row repeats
        options = [x for x in {d, d[:2], d[-2:], d[:3], d[-3:], d[:4], d[-4:]}
                   if len(x) >= 2 and not re.search(r"(.)\1\1", x)]
        digits = secrets.choice(options) if options else None
    if digits is None and f.day:
        digits = f.day + f.month
    tail = (f.favs[0].lower() if f.favs else None) or (f.name.lower() if f.name else None) or f.core[:3].lower()
    mid = f"{_sym()}{digits}" if digits else ""
    return f"{f.core.capitalize()}{mid}{_sym()}{tail}"


PATTERNS = [
    ("Short & familiar", "Start of your name, birth day, start of a favourite, then the year.", ("name", "fav", "dob"), _short),
    ("Favourite first", "A favourite thing, the start of your name, then the year.", ("name", "fav", "dob"), _reverse),
    ("Name + favourite", "Your name and a favourite thing in full, with your birth day and month.", ("name", "fav", "dob"), _full),
    ("Favourite + name", "A favourite thing, your name, then birth month and year.", ("name", "fav", "dob"), _flip),
    ("Two favourites", "Two of your favourite things with your birth day and year.", ("fav2", "dob"), _two_favs),
    ("Name + birth year", "Your name, your birth year and birth day.", ("name", "dob"), _year),
    ("Name + date", "Your name with your birth day, month and year in pieces.", ("name", "dob"), _name_dob),
    ("Name + favourite (no date)", "Your name, a favourite thing, and the start of your name in capitals.", ("name", "fav"), _name_fav),
]

KEEP_YOURS = ("Your password, tidied up",
              "Keeps the word and numbers from your current password, adds symbols and one of your details.",
              ("core",), _keep_yours)


def _build(title, why, fn, frags):
    """Retry (new symbols each time) until the analyzer accepts it: no common /
    sequential / repeated / keyboard-walk pattern and a decent score."""
    for _ in range(25):
        value = fn(frags)
        result = analyzer.analyze_password(value)
        c = result["checks"]
        if (result["score"] >= MIN_SCORE and c["not_common_password"]
                and c["no_sequential_pattern"] and c["no_repeated_pattern"]
                and c["no_keyboard_walk"]):
            return {
                "pattern": title,
                "description": why,
                "value": value,
                "targeted_strength": HINT,
                "analysis": result,
            }
    return None


def suggest(profile: dict, base_password: str = "", count: int = DEFAULT_COUNT) -> dict:
    """profile: {name, dob, favorites}. base_password: optional existing password.
    Returns up to `count` suggestions (default 2) built only from the user's input."""
    profile = {
        "name": _clean(profile.get("name")),
        "dob": _clean(profile.get("dob"), 20),
        "favorites": _clean(profile.get("favorites"), 256),
    }
    base_password = (base_password or "")[:256]
    count = max(1, min(int(count), MAX_COUNT))
    frags = _Frags(profile, base_password)

    warnings = []
    if base_password:
        low = base_password.lower()
        leaked = [w for w in _tokens(profile["name"], profile["favorites"]) if len(w) >= 3 and w.lower() in low]
        if leaked:
            warnings.append("Your current password contains personal details you entered "
                            "(" + ", ".join(leaked) + ") -- that makes it easy to guess for anyone who knows you.")
        dob = _dob_digits(profile["dob"])
        if dob and (dob[2] in base_password or dob[0] + dob[1] in base_password):
            warnings.append("Your current password appears to contain your date of birth.")

    pool = [p for p in PATTERNS if all(frags.has(n) for n in p[2])]
    pool = _shuffled(pool)
    if base_password and frags.has("core"):
        pool.insert(0, KEEP_YOURS)   # your own password's upgrade comes first

    suggestions, seen = [], set()
    for title, why, _need, fn in pool:
        built = _build(title, why, fn, frags)
        if built and built["value"] not in seen:
            seen.add(built["value"])
            suggestions.append(built)
        if len(suggestions) == count:
            break

    note = NOTE
    if not suggestions:
        note = ("Not enough to build from. Add a favourite thing or your date of birth "
                "(together with your name) to get suggestions.")
    return {"suggestions": suggestions, "warnings": warnings, "note": note,
            "can_refresh": len(pool) > len(suggestions)}
