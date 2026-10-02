from src.demo_client import DemoClient

ORG = "100000"


def test_demo_serves_org_inventory():
    client = DemoClient()
    assert client.verify_connection()[0]["id"] == ORG
    assert len(list(client.paginate(f"/organizations/{ORG}/networks"))) == 3


def test_inapplicable_endpoint_behaves_like_404():
    client = DemoClient()
    # An access point has no switch ports; the real API 404s, so must the demo.
    assert client.get_optional("/devices/Q2XX-HQ00-AP01/switch/ports", default=[]) == []


def test_query_string_is_ignored_for_routing():
    client = DemoClient()
    assert client.get(f"/organizations/{ORG}/devices?perPage=1000")
