import pytest

from app import app


@pytest.fixture
def client():
    return app.test_client()


def test_generate_password(client):
    r = client.post("/api/generate", json={"length": 20})
    assert r.status_code == 200
    d = r.get_json()
    assert len(d["value"]) == 20 and d["analysis"]["score"] > 0


def test_generate_passphrase(client):
    d = client.post("/api/generate", json={"mode": "passphrase", "words": 4}).get_json()
    assert len(d["value"].split("-")) == 4


@pytest.mark.parametrize("body", [{"length": 2}, {"length": "abc"}, {"mode": "passphrase", "words": 99}])
def test_generate_bad_input(client, body):
    assert client.post("/api/generate", json=body).status_code == 400


def test_wordlist(client):
    assert len(client.get("/api/wordlist").get_json()["words"]) == 2048


def test_personalize(client):
    r = client.post("/api/personalize", json={"name": "Asha Rao", "favorites": "tennis, mango"})
    assert r.status_code == 200 and len(r.get_json()["suggestions"]) >= 3


def test_personalize_requires_input(client):
    assert client.post("/api/personalize", json={}).status_code == 400


def test_personalize_rejects_oversized_base(client):
    assert client.post("/api/personalize", json={"base_password": "a" * 300}).status_code == 400
