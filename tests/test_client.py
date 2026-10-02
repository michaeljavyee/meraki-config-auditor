import inspect

import pytest
import responses

from src import meraki_client
from src.meraki_client import (
    MerakiAuthError,
    MerakiClient,
    MerakiNotFoundError,
    MerakiRateLimitError,
)

BASE = "https://api.meraki.com/api/v1"


@pytest.fixture
def client():
    return MerakiClient("test-key-not-real")


def test_requires_key():
    with pytest.raises(ValueError):
        MerakiClient("")


@responses.activate
def test_sends_bearer_auth(client):
    responses.get(f"{BASE}/organizations", json=[{"id": "1"}])
    client.get("/organizations")
    assert responses.calls[0].request.headers["Authorization"] == "Bearer test-key-not-real"


@responses.activate
def test_paginate_follows_link_header(client):
    page2 = f"{BASE}/organizations/1/devices?perPage=2&startingAfter=Q2XX"
    responses.get(
        f"{BASE}/organizations/1/devices",
        json=[{"serial": "A"}, {"serial": "B"}],
        headers={"Link": f'<{page2}>; rel=next'},
    )
    responses.get(page2, json=[{"serial": "C"}])
    serials = [d["serial"] for d in client.paginate("/organizations/1/devices", {"perPage": 2})]
    assert serials == ["A", "B", "C"]
    # The cursor URL is followed verbatim; params are not re-sent on page 2.
    assert responses.calls[1].request.url == page2


@responses.activate
def test_retries_on_429_using_retry_after(client, monkeypatch):
    sleeps = []
    monkeypatch.setattr(meraki_client.time, "sleep", sleeps.append)
    responses.get(f"{BASE}/organizations", status=429, headers={"Retry-After": "3"})
    responses.get(f"{BASE}/organizations", json=[])
    assert client.get("/organizations") == []
    assert sleeps == [3.0]


@responses.activate
def test_gives_up_after_max_retries(client, monkeypatch):
    monkeypatch.setattr(meraki_client.time, "sleep", lambda s: None)
    for _ in range(meraki_client.MAX_RETRIES):
        responses.get(f"{BASE}/organizations", status=429, headers={"Retry-After": "1"})
    with pytest.raises(MerakiRateLimitError):
        client.get("/organizations")


@responses.activate
def test_401_names_the_fix(client):
    responses.get(f"{BASE}/organizations", status=401, json={"errors": ["Invalid API key"]})
    with pytest.raises(MerakiAuthError) as exc:
        client.get("/organizations")
    assert "MERAKI_API_KEY" in str(exc.value)
    assert "test-key-not-real" not in str(exc.value)  # never leak the key


@responses.activate
def test_get_optional_returns_default_for_inapplicable_endpoint(client):
    responses.get(f"{BASE}/networks/N1/appliance/vlans", status=400,
                  json={"errors": ["VLANs are not enabled for this network"]})
    assert client.get_optional("/networks/N1/appliance/vlans", default=[]) == []


@responses.activate
def test_404_raises_not_found(client):
    responses.get(f"{BASE}/networks/N1/wireless/ssids", status=404)
    with pytest.raises(MerakiNotFoundError):
        client.get("/networks/N1/wireless/ssids")


def test_client_has_no_write_methods():
    """The read-only claim, checked from inside the test suite as well as CI."""
    source = inspect.getsource(meraki_client)
    for verb in ("post", "put", "patch", "delete"):
        assert f"session.{verb}(" not in source
        assert f"requests.{verb}(" not in source
    public = {n for n in dir(MerakiClient) if not n.startswith("_")}
    assert not public & {"post", "put", "patch", "delete", "update", "create"}
