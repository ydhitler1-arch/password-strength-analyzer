import re

import pytest

import personalized as p

PROFILE = {"name": "Devan", "dob": "13/05/2006", "favorites": "games, anime"}


def _alnum_chunks(value):
    return [c for c in re.split(r"[^A-Za-z0-9]+", value) if c]


def test_returns_two_by_default_and_respects_count():
    assert len(p.suggest(PROFILE)["suggestions"]) == 2
    assert len(p.suggest(PROFILE, count=1)["suggestions"]) == 1
    assert len(p.suggest(PROFILE, count=99)["suggestions"]) <= p.MAX_COUNT


def test_suggestions_are_analyzed_and_acceptable():
    for _ in range(30):
        for s in p.suggest(PROFILE)["suggestions"]:
            a = s["analysis"]
            assert a["score"] >= p.MIN_SCORE
            c = a["checks"]
            assert c["not_common_password"] and c["no_sequential_pattern"]
            assert c["no_repeated_pattern"] and c["no_keyboard_walk"]


def test_only_users_words_and_numbers_are_used():
    """Every alphanumeric chunk must be built from the user's own fragments."""
    allowed_text = "devan games anime"
    for _ in range(100):
        for s in p.suggest(PROFILE, count=4)["suggestions"]:
            for chunk in _alnum_chunks(s["value"]):
                for part in re.findall(r"[A-Za-z]+|\d+", chunk):
                    if part.isdigit():
                        # only combinations of day 13, month 05, year 2006 / yy 06
                        assert re.fullmatch(r"(2006|13|05|06)+", part), (s["value"], part)
                    else:
                        assert part.lower() in allowed_text, (s["value"], part)


def test_no_random_words_when_a_field_is_missing():
    out = p.suggest({"name": "Devan", "favorites": "cricket"}, count=4)
    for s in out["suggestions"]:
        for part in re.findall(r"[A-Za-z]+", s["value"]):
            assert part.lower() in ("devan", "cricket", "dev"), s["value"]
        assert not re.search(r"\d", s["value"])


def test_suggestions_differ_and_refresh_changes_them():
    out = p.suggest(PROFILE, count=4)
    values = [s["value"] for s in out["suggestions"]]
    assert len(set(values)) == len(values)
    seen = {s["value"] for _ in range(20) for s in p.suggest(PROFILE)["suggestions"]}
    assert len(seen) > 4


def test_not_enough_input_gives_message_not_random_password():
    out = p.suggest({"name": "Devan"})
    assert out["suggestions"] == [] and "Add a favourite" in out["note"]


def test_keep_yours_flow_uses_own_password_and_warns():
    out = p.suggest({"name": "Rahul", "dob": "14/07/1999", "favorites": "cricket"}, base_password="rahul1999")
    first = out["suggestions"][0]
    assert first["pattern"] == "Your password, tidied up"
    assert first["value"].lower().startswith("rahul")
    assert first["analysis"]["score"] >= p.MIN_SCORE
    assert len(out["warnings"]) == 2


def test_keep_yours_with_only_a_password():
    out = p.suggest({}, base_password="sunshine")
    assert out["suggestions"] and out["suggestions"][0]["value"].lower().startswith("sunshine")


def test_digits_with_triple_repeats_are_sliced_not_dropped():
    # "1999" has 999 -> analyzer rejects it whole, so a slice must be used
    for _ in range(20):
        out = p.suggest({}, base_password="rahul1999")
        assert out["suggestions"]
        assert "1999" not in out["suggestions"][0]["value"]


def test_dob_parsing():
    assert p._dob_digits("14/07/1999") == ("14", "07", "1999")
    assert p._dob_digits("1999-7-4") == ("04", "07", "1999")
    assert p._dob_digits("13052006") == ("13", "05", "2006")
    assert p._dob_digits("nonsense") is None


def test_tokens_sanitised_and_bounded():
    toks = p._tokens("a, b!!, hello-world  hello", "x" * 100)
    assert "hello" in [t.lower() for t in toks] and len(toks) == len({t.lower() for t in toks})
    assert all(len(t) <= p.MAX_TOKEN_LEN for t in toks)
