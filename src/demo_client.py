"""A stand-in for MerakiClient that serves bundled JSON fixtures.

WHY THIS EXISTS: a reviewer will clone the repo and run one command. They will
not have a Meraki organization. `--demo` has to produce the full report with no
credentials and no network, which means every check runs against fixture data.

WHY IT'S SHAPED LIKE THE REAL CLIENT: DemoClient exposes the same methods as
MerakiClient (get, paginate, get_optional, verify_connection), so the checks
can't tell which one they were handed. There is exactly one code path through
the checks, and `--demo` exercises it rather than a parallel imitation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


class _Missing:
    """Sentinel for "no such resource", distinct from a legitimate None/[]."""

    def __repr__(self) -> str:  # pragma: no cover
        return "<MISSING>"


_MISSING = _Missing()

# (path regex, fixture file, keyed-by group index or None for whole file)
_ROUTES = [
    (r"/organizations", "organizations", None),
    (r"/organizations/[^/]+/networks", "networks", None),
    (r"/organizations/[^/]+/devices", "devices", None),
    (r"/devices/([^/]+)/switch/ports", "switch_ports", 1),
    (r"/networks/([^/]+)/appliance/vlans", "appliance_vlans", 1),
    (r"/networks/([^/]+)/appliance/ports", "appliance_ports", 1),
    (r"/networks/([^/]+)/appliance/firewall/l3FirewallRules", "l3_firewall_rules", 1),
    (r"/networks/([^/]+)/wireless/ssids", "ssids", 1),
    (r"/networks/([^/]+)/topology/linkLayer", "topology", 1),
]


class DemoClient:
    """Serves fixture JSON in response to Dashboard API paths."""

    base_url = "https://api.meraki.com/api/v1 (demo fixtures)"

    def __init__(self, fixture_dir: Optional[Path] = None) -> None:
        self.fixture_dir = Path(fixture_dir) if fixture_dir else FIXTURE_DIR
        if not self.fixture_dir.exists():
            raise FileNotFoundError(
                f"Fixture directory not found: {self.fixture_dir}\n"
                "  Regenerate it with: python scripts/generate_fixtures.py"
            )
        self._cache: Dict[str, Any] = {}

    def _load(self, name: str) -> Any:
        if name not in self._cache:
            path = self.fixture_dir / f"{name}.json"
            if not path.exists():
                raise FileNotFoundError(f"Missing fixture: {path}")
            self._cache[name] = json.loads(path.read_text())
        return self._cache[name]

    def _resolve(self, path: str) -> Any:
        path = "/" + path.split("?")[0].strip("/")
        for pattern, fixture, group in _ROUTES:
            match = re.fullmatch(pattern, path)
            if not match:
                continue
            data = self._load(fixture)
            if group is None:
                return data
            # A key absent from a keyed fixture behaves like the real API's
            # 404/400 for "this product isn't in this network", so the
            # not-applicable handling in the checks is exercised in demo mode.
            return data.get(match.group(group), _MISSING)
        return _MISSING

    # ------------------------------------------------------------------- public

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        result = self._resolve(path)
        if result is _MISSING:
            raise FileNotFoundError(f"No demo fixture models {path}")
        return result

    def get_optional(
        self, path: str, params: Optional[Dict[str, Any]] = None, default: Any = None
    ) -> Any:
        result = self._resolve(path)
        return default if result is _MISSING else result

    def paginate(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Iterator[Dict[str, Any]]:
        yield from _as_list(self.get(path, params=params))

    def verify_connection(self) -> Any:
        return self._load("organizations")

    def close(self) -> None:  # parity with MerakiClient
        pass

    def __enter__(self) -> "DemoClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _as_list(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]
