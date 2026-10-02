from pathlib import Path

import pytest

from src.baseline import load_baseline
from src.checks.base import OrgContext
from src.demo_client import DemoClient

EXAMPLE_BASELINE = Path(__file__).resolve().parent.parent / "baselines" / "example.yaml"


@pytest.fixture
def baseline():
    return load_baseline(EXAMPLE_BASELINE)


@pytest.fixture
def demo_context(baseline):
    client = DemoClient()
    org = client.verify_connection()[0]
    return OrgContext(client, org, baseline)


class StubClient:
    """Serve a dict of {path: payload}; anything else behaves like a 404."""

    def __init__(self, routes):
        self.routes = routes

    def get(self, path, params=None):
        return self.routes[path]

    def get_optional(self, path, params=None, default=None):
        return self.routes.get(path, default)

    def paginate(self, path, params=None):
        yield from self.routes.get(path, [])


@pytest.fixture
def stub_context(baseline):
    def build(routes):
        return OrgContext(StubClient(routes), {"id": "1", "name": "Stub"}, baseline)
    return build
