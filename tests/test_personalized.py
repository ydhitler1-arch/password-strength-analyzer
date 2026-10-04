import pytest

import personalized as p

PROFILE = {"name": "Rahul Sharma", "dob": "14/07/1999", "favorites": "cricket, biryani, Hyderabad"}


def _tier(out, tier):
    return [s for s in out["suggestions"] if s["tier"] == tier]


def test_returns_easy_and_strong_suggestions():
    out = p.suggest(PROFILE)
    assert len(_tier(out, "easy")) >= 3 and len(_tier(out, "strong")) >= 3
    # easy ones come first
    tiers = [s["tier"] for s in out["suggestions"]]
    assert tiers == sorted(tiers, key=lambda t: t != "easy")
    for s in _tier(out, "strong"):
        a = s["analysis"]
        assert a["score"] >= p.MIN_ACCEPT_SCORE
        assert a["checks"]["not_common_password"]
        assert not a["patterns_detected"]["year_or_date"]
        assert s["random_entropy_bits"] > 40
    for s in _tier(out, "easy"):
        assert s["analysis"]["score"] >= p.MIN_EASY_SCORE
        assert s["analysis"]["checks"]["not_common_password"]


def test_easy_suggestions_are_readable_and_use_the_details():
    out = p.suggest({"name": "Devan", "dob": "13/05/2006", "favorites": "cricket"})
    easy = _tier(out, "easy")
    assert easy
    for s in easy:
        low = s["value"].lower()
        assert "dev" in low or "cricket" in low or "cric" in low
        assert len(s["value"]) >= 10
    assert any("13" in s["value"] for s in easy)


def test_easy_suggestions_work_with_only_a_name():
    easy = _tier(p.suggest({"name": "Devan"}), "easy")
    assert len(easy) >= 3 and all("dev" in s["value"].lower() for s in easy)


def test_suggestions_differ():
    values = [s["value"] for s in p.suggest(PROFILE)["suggestions"]]
    assert len(set(values)) == len(values)


def test_raw_dob_never_embedded():
    for _ in range(30):
        for s in _tier(p.suggest(PROFILE), "strong"):
            assert "1999" not in s["value"] and "14/07" not in s["value"]


def test_upgrade_flow_warns_and_adds_option():
    out = p.suggest(PROFILE, base_password="rahul1999")
    assert out["suggestions"][0]["pattern"] == "Your password, kept readable"
    assert any(s["pattern"].startswith("Upgrade of your password") for s in out["suggestions"])
    assert len(out["warnings"]) == 2


def test_upgrade_without_details():
    out = p.suggest({}, base_password="sunshine")
    assert any(s["pattern"].startswith("Upgrade of your password") for s in out["suggestions"])


def test_too_few_details_falls_back_to_random():
    out = p.suggest({"name": "X"})
    assert [s["pattern"] for s in out["suggestions"]] == ["Fully random"]


def test_dob_parsing():
    assert p._dob_digits("14/07/1999") == ("14", "07", "1999")
    assert p._dob_digits("1999-7-4") == ("04", "07", "1999")
    assert p._dob_digits("13052006") == ("13", "05", "2006")
    assert p._dob_digits("nonsense") is None


def test_tokens_sanitised_and_bounded():
    toks = p._tokens("a, b!!, hello-world  hello", "x" * 100)
    assert "hello" in [t.lower() for t in toks] and len(toks) == len({t.lower() for t in toks})
    assert all(len(t) <= p.MAX_TOKEN_LEN for t in toks)
