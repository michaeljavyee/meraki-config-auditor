"""Shared organization data, fetched once and reused by every check.

Several checks need the same things: the network list, the device list, each
switch's ports. Without a shared context, adding a check would add another
pass over every switch in the org, and the Dashboard API's per-org rate limit
is shared with every other integration the customer runs.

OrgContext loads each piece on first request and caches it (lazy loading), so
checks stay independent functions that never worry about who fetched what.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..baseline import Baseline

logger = logging.getLogger(__name__)

# How far back to look for observed clients. The API allows up to 31 days;
# a week covers a full working cycle without reaching back to devices that
# have long since left.
CLIENT_WINDOW_DAYS = 7


class OrgContext:
    """Lazily-loaded, cached, read-only view of one Meraki organization."""

    def __init__(self, client: Any, org: Dict[str, Any], baseline: Baseline) -> None:
        self.client = client
        self.org = org
        self.org_id = str(org["id"])
        self.baseline = baseline
        self.scope_limitations: List[str] = []
        # Per-VLAN address-space summary, filled in by the IPAM check and
        # rendered as its own table in the report.
        self.address_space: List[Dict[str, Any]] = []

        self._networks: Optional[List[Dict[str, Any]]] = None
        self._devices: Optional[List[Dict[str, Any]]] = None
        self._switch_ports: Dict[str, List[Dict[str, Any]]] = {}
        self._per_network: Dict[str, Dict[str, Any]] = {}

    # --------------------------------------------------------------- networks

    @property
    def all_networks(self) -> List[Dict[str, Any]]:
        if self._networks is None:
            logger.info("Fetching networks")
            self._networks = list(
                self.client.paginate(
                    f"/organizations/{self.org_id}/networks", params={"perPage": 1000}
                )
            )
        return self._networks

    @property
    def networks(self) -> List[Dict[str, Any]]:
        """Networks in scope for the baseline, sorted by name for stable output."""
        in_scope = [n for n in self.all_networks if self.baseline.applies_to(n)]
        return sorted(in_scope, key=lambda n: n.get("name", ""))

    def network_name(self, network_id: str) -> str:
        for network in self.all_networks:
            if network.get("id") == network_id:
                return network.get("name") or network_id
        return network_id

    @staticmethod
    def has_product(network: Dict[str, Any], product: str) -> bool:
        return product in (network.get("productTypes") or [])

    # ---------------------------------------------------------------- devices

    @property
    def devices(self) -> List[Dict[str, Any]]:
        if self._devices is None:
            logger.info("Fetching device inventory")
            self._devices = list(
                self.client.paginate(
                    f"/organizations/{self.org_id}/devices", params={"perPage": 1000}
                )
            )
        return self._devices

    @property
    def devices_by_serial(self) -> Dict[str, Dict[str, Any]]:
        return {d["serial"]: d for d in self.devices if d.get("serial")}

    def devices_in(self, network_id: str, product_type: Optional[str] = None) -> List[Dict[str, Any]]:
        found = [d for d in self.devices if d.get("networkId") == network_id]
        if product_type:
            found = [d for d in found if product_type_of(d) == product_type]
        return sorted(found, key=lambda d: d.get("name") or d.get("serial", ""))

    def device_name(self, serial: str) -> str:
        device = self.devices_by_serial.get(serial) or {}
        return device.get("name") or serial

    # ---------------------------------------------------- per-device / network

    def switch_ports(self, serial: str) -> List[Dict[str, Any]]:
        if serial not in self._switch_ports:
            self._switch_ports[serial] = list(
                self.client.get_optional(f"/devices/{serial}/switch/ports", default=[]) or []
            )
        return self._switch_ports[serial]

    def _network_resource(self, network_id: str, key: str, path: str, default: Any) -> Any:
        cache = self._per_network.setdefault(network_id, {})
        if key not in cache:
            cache[key] = self.client.get_optional(path, default=default)
        return cache[key]

    def appliance_vlans(self, network_id: str) -> List[Dict[str, Any]]:
        return self._network_resource(
            network_id, "vlans", f"/networks/{network_id}/appliance/vlans", []
        ) or []

    def appliance_ports(self, network_id: str) -> List[Dict[str, Any]]:
        return self._network_resource(
            network_id, "mx_ports", f"/networks/{network_id}/appliance/ports", []
        ) or []

    def l3_firewall_rules(self, network_id: str) -> Optional[List[Dict[str, Any]]]:
        """Rules in evaluation order, or None if the network has no MX."""
        payload = self._network_resource(
            network_id, "l3", f"/networks/{network_id}/appliance/firewall/l3FirewallRules", None
        )
        if payload is None:
            return None
        return list(payload.get("rules") or [])

    def ssids(self, network_id: str) -> List[Dict[str, Any]]:
        return self._network_resource(
            network_id, "ssids", f"/networks/{network_id}/wireless/ssids", []
        ) or []

    def clients(self, network_id: str) -> List[Dict[str, Any]]:
        """Clients seen in the last CLIENT_WINDOW_DAYS, or [] if unavailable.

        Observed clients are evidence of what's actually using address space,
        as opposed to what the configuration says should be. The endpoint is
        paginated and can be large, so it is only read by checks that need it.
        """
        cache = self._per_network.setdefault(network_id, {})
        if "clients" not in cache:
            try:
                cache["clients"] = list(self.client.paginate(
                    f"/networks/{network_id}/clients",
                    params={"timespan": CLIENT_WINDOW_DAYS * 86400, "perPage": 1000},
                ))
            except Exception as exc:  # noqa: BLE001 - absence is a limitation, not a crash
                logger.info("Clients unavailable for %s: %s", network_id, exc)
                self.note_limitation(
                    f"Client data could not be read for {self.network_name(network_id)}, so "
                    "address usage there is based on configuration only."
                )
                cache["clients"] = []
        return cache["clients"]

    def link_layer(self, network_id: str) -> Optional[Dict[str, Any]]:
        return self._network_resource(
            network_id, "topology", f"/networks/{network_id}/topology/linkLayer", None
        )

    # ------------------------------------------------------------------- misc

    def note_limitation(self, text: str) -> None:
        if text not in self.scope_limitations:
            self.scope_limitations.append(text)


def product_type_of(device: Dict[str, Any]) -> str:
    """productType, falling back to the model prefix for older API responses."""
    if device.get("productType"):
        return str(device["productType"])
    model = str(device.get("model") or "").upper()
    for prefix, product in (
        ("MX", "appliance"), ("Z", "appliance"), ("MS", "switch"),
        ("MR", "wireless"), ("CW", "wireless"), ("MV", "camera"),
        ("MG", "cellularGateway"), ("MT", "sensor"),
    ):
        if model.startswith(prefix):
            return product
    return "unknown"
