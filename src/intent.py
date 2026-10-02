"""Load and validate an intent file: the declared configuration of networks.

Intent is not the same thing as the audit baseline.

  * The **baseline** is a policy that applies to every network: "every uplink
    carries VLAN 40", "no open SSIDs". It is compared loosely and reported as
    findings with severities.
  * **Intent** is the exact configuration of specific networks: "port 8 on
    SW-WEST-IDF1 is a trunk allowing 1,10,20,30,40". It is compared exactly
    and reported as a plan of changes.

The baseline answers "is this network compliant?". Intent answers "is this
network configured the way we said it would be, and if not, what would have
to change?".

An intent file can be one YAML file or a directory of them (one per network
is a natural layout); a directory is merged, and declaring the same network
twice is an error rather than a silent override.

Only declared attributes are managed. If intent says nothing about a port's
PoE setting, the plan says nothing about it either. That is what makes it
safe to adopt incrementally: start by declaring the uplinks, add the rest
later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import yaml

from .state import KINDS, L3_RULE_ATTRS, MANAGED_ATTRS

# Sections where `exclusive` is allowed: a live item that intent doesn't
# declare is planned for deletion. Switch ports are physical and SSID slots
# always exist, so neither can be "deleted"; firewall rules are already an
# exact ordered list.
EXCLUSIVE_ALLOWED = {"appliance_vlans"}

REQUIRED_RULE_ATTRS = ("policy", "protocol", "srcCidr", "destCidr")


class IntentError(ValueError):
    """The intent file is missing, unparseable, or structurally invalid."""


@dataclass
class Intent:
    source: str
    networks: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    exclusive: Dict[str, List[str]] = field(default_factory=dict)


def load_intent(path: Path) -> Intent:
    path = Path(path)
    if not path.exists():
        raise IntentError(
            f"Intent not found: {path}\n"
            "  Create one from live config with:  python -m src.export --output intent/mine.yaml"
        )
    files = sorted(path.glob("*.y*ml")) if path.is_dir() else [path]
    if not files:
        raise IntentError(f"No .yaml files in {path}")

    intent = Intent(source=str(path))
    for file in files:
        try:
            raw = yaml.safe_load(file.read_text()) or {}
        except yaml.YAMLError as exc:
            raise IntentError(f"Could not parse {file}: {exc}") from exc
        networks = raw.get("networks")
        if not isinstance(networks, dict) or not networks:
            raise IntentError(f"{file}: expected a non-empty 'networks:' mapping")
        for name, body in networks.items():
            name = str(name)
            if name in intent.networks:
                raise IntentError(f"Network '{name}' is declared in more than one intent file")
            intent.networks[name], intent.exclusive[name] = _validate_network(file, name, body or {})
    return intent


def _validate_network(file: Path, name: str, body: Dict[str, Any]):
    where = f"{file}: networks.{name}"
    if not isinstance(body, dict):
        raise IntentError(f"{where}: must be a mapping")

    exclusive = [str(x) for x in body.get("exclusive") or []]
    for section in exclusive:
        if section not in EXCLUSIVE_ALLOWED:
            raise IntentError(
                f"{where}.exclusive: '{section}' can't be exclusive "
                f"(allowed: {', '.join(sorted(EXCLUSIVE_ALLOWED))})"
            )

    unknown = set(body) - set(KINDS) - {"exclusive"}
    if unknown:
        raise IntentError(
            f"{where}: unknown section(s) {', '.join(sorted(unknown))}. Use: {', '.join(KINDS)}"
        )

    out: Dict[str, Any] = {}
    if "appliance_vlans" in body:
        out["appliance_vlans"] = {
            _vlan_id(k, f"{where}.appliance_vlans"): _attrs(v, "appliance_vlans", f"{where}.appliance_vlans.{k}")
            for k, v in (body["appliance_vlans"] or {}).items()
        }
    if "l3_firewall_rules" in body:
        rules = body["l3_firewall_rules"] or []
        if not isinstance(rules, list):
            raise IntentError(f"{where}.l3_firewall_rules: must be an ordered list")
        for i, rule in enumerate(rules):
            missing = [a for a in REQUIRED_RULE_ATTRS if a not in (rule or {})]
            if missing:
                raise IntentError(f"{where}.l3_firewall_rules[{i}]: missing {', '.join(missing)}")
            extra = set(rule) - set(L3_RULE_ATTRS)
            if extra:
                raise IntentError(f"{where}.l3_firewall_rules[{i}]: unknown field(s) {', '.join(sorted(extra))}")
        out["l3_firewall_rules"] = list(rules)
    if "switch_ports" in body:
        out["switch_ports"] = {
            str(switch): {
                str(port): _attrs(attrs, "switch_ports", f"{where}.switch_ports.{switch}.{port}")
                for port, attrs in (ports or {}).items()
            }
            for switch, ports in (body["switch_ports"] or {}).items()
        }
    if "ssids" in body:
        ssids = {}
        for number, attrs in (body["ssids"] or {}).items():
            n = int(number)
            if not 0 <= n <= 14:
                raise IntentError(f"{where}.ssids.{number}: SSID number must be 0-14")
            ssids[n] = _attrs(attrs, "ssids", f"{where}.ssids.{number}")
        out["ssids"] = ssids
    return out, exclusive


def _attrs(value: Any, kind: str, where: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise IntentError(f"{where}: must be a mapping of attributes")
    unknown = set(value) - set(MANAGED_ATTRS[kind])
    if unknown:
        raise IntentError(
            f"{where}: unknown attribute(s) {', '.join(sorted(unknown))}. "
            f"Managed attributes for {kind}: {', '.join(MANAGED_ATTRS[kind])}"
        )
    return dict(value)


def _vlan_id(value: Any, where: str) -> int:
    try:
        vid = int(value)
    except (TypeError, ValueError) as exc:
        raise IntentError(f"{where}: {value!r} is not a VLAN ID") from exc
    if not 1 <= vid <= 4094:
        raise IntentError(f"{where}: {vid} is outside 1-4094")
    return vid
