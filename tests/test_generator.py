import string

import pytest

import generator


def test_password_length_and_classes():
    for _ in range(100):
        pw = generator.generate_password(12)["value"]
        assert len(pw) == 12
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in generator.SYMBOLS for c in pw)


def test_password_options_respected():
    pw = generator.generate_password(40, symbols=False, digits=False)["value"]
    assert pw.isalpha()
    pw = generator.generate_password(60, avoid_ambiguous=True)["value"]
    assert not set(pw) & generator.AMBIGUOUS


def test_password_entropy_value():
    out = generator.generate_password(16, uppercase=False, symbols=False, digits=False)
    assert out["generator_entropy_bits"] == pytest.approx(16 * 4.7, abs=0.1)


@pytest.mark.parametrize("kwargs", [{"length": 7}, {"length": 129},
                                    {"lowercase": False, "uppercase": False,
                                     "digits": False, "symbols": False}])
def test_password_rejects_bad_input(kwargs):
    with pytest.raises(ValueError):
        generator.generate_password(**kwargs)


def test_passphrase_shape_and_entropy():
    out = generator.generate_passphrase(words=5, separator="-", capitalize=True, add_number=True)
    parts = out["value"][:-1].split("-")
    assert len(parts) == 5 and all(p[0].isupper() for p in parts)
    assert out["value"][-1].isdigit()
    assert out["generator_entropy_bits"] == pytest.approx(5 * 11 + 3.3, abs=0.1)


def test_passphrase_rejects_bad_input():
    with pytest.raises(ValueError):
        generator.generate_passphrase(words=2)
    with pytest.raises(ValueError):
        generator.generate_passphrase(separator="x")


def test_wordlist_is_2048_unique():
    assert len(generator.WORDLIST) == 2048 == len(set(generator.WORDLIST))


def test_outputs_vary():
    assert len({generator.generate_password(20)["value"] for _ in range(50)}) == 50
