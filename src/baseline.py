"""The declared standard every network is measured against.

Drift is only meaningful relative to something. The baseline is a YAML file
that states what "correct" looks like for this organization: target firmware,
which VLANs every uplink trunk must carry, the firewall policy every site
should have, and the SSIDs every site should broadcast.

Keeping the standard in a file rather than in code is deliberate. It can be
reviewed in a pull request, versioned alongside the change that motivated it,
and diffed when someone asks "when did the standard change?". That is the
same property the tool is checking for in the network.

See docs/baseline-format.md for every field.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class BaselineError(ValueError):
    """The baseline file is missing, unparseable, or structurally wrong."""


@dataclass
class TrunkStandard:
    required_vlans: List[int] = field(default_factory=list)
    native_vlan: Optional[int] = None
    uplink_port_tags: List[str] = field(default_factory=lambda: ["uplink"])
    uplink_name_patterns: List[str] = field(default_factory=lambda: ["uplink"])


@dataclass
class NacStandard:
    required: bool = False
    exempt_port_tags: List[str] = field(default_factory=lambda: ["uplink", "nac-exempt"])
    guest_vlan_roles: List[str] = field(default_factory=lambda: ["guest"])
    min_radius_servers: int = 2


@dataclass
class Baseline:
    name: str
    version: str
    source: str
    firmware: Dict[str, str] = field(default_factory=dict)
    vlan_names: Dict[int, str] = field(default_factory=dict)
    trunks: TrunkStandard = field(default_factory=TrunkStandard)
    firewall_rules: List[Dict[str, Any]] = field(default_factory=list)
    ssids: List[Dict[str, Any]] = field(default_factory=list)
    network_tags: List[str] = field(default_factory=list)
    nac: NacStandard = field(default_factory=NacStandard)

    def vlan_label(self, vlan_id: int) -> str:
        name = self.vlan_names.get(vlan_id)
        return f"VLAN {vlan_id} ({name})" if name else f"VLAN {vlan_id}"

    def applies_to(self, network: Dict[str, Any]) -> bool:
        if not self.network_tags:
            return True
        return bool(set(self.network_tags) & set(network.get("tags") or []))


def load_baseline(path: Path) -> Baseline:
    path = Path(path)
    if not path.exists():
        raise BaselineError(
            f"Baseline file not found: {path}\n"
            "  Start from baselines/example.yaml and adjust it to your standard."
        )
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise BaselineError(f"Could not parse {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise BaselineError(f"{path}: top level must be a mapping")

    trunks_raw = raw.get("trunks") or {}
    trunks = TrunkStandard(
        required_vlans=[_vlan(v, path, "trunks.required_vlans") for v in trunks_raw.get("required_vlans") or []],
        native_vlan=_vlan(trunks_raw["native_vlan"], path, "trunks.native_vlan")
        if trunks_raw.get("native_vlan") is not None
        else None,
        uplink_port_tags=[str(t) for t in trunks_raw.get("uplink_port_tags") or ["uplink"]],
        uplink_name_patterns=[str(p).lower() for p in trunks_raw.get("uplink_name_patterns") or ["uplink"]],
    )

    vlan_names = {
        _vlan(k, path, "vlans"): str(v) for k, v in (raw.get("vlans") or {}).items()
    }

    rules = (raw.get("firewall") or {}).get("l3_rules") or []
    for index, rule in enumerate(rules):
        for required in ("policy", "protocol", "srcCidr", "destCidr"):
            if required not in rule:
                raise BaselineError(
                    f"{path}: firewall.l3_rules[{index}] is missing '{required}'"
                )
        if str(rule["policy"]).lower() not in ("allow", "deny"):
            raise BaselineError(
                f"{path}: firewall.l3_rules[{index}].policy must be allow or deny"
            )

    ssids = raw.get("ssids") or []
    for index, ssid in enumerate(ssids):
        if "name" not in ssid:
            raise BaselineError(f"{path}: ssids[{index}] is missing 'name'")

    firmware = {str(k): str(v) for k, v in (raw.get("firmware") or {}).items()}

    nac_raw = raw.get("nac") or {}
    nac = NacStandard(
        required=bool(nac_raw.get("required_on_access_ports", False)),
        exempt_port_tags=[str(t).lower() for t in nac_raw.get("exempt_port_tags") or ["uplink", "nac-exempt"]],
        guest_vlan_roles=[str(r).lower() for r in nac_raw.get("guest_vlan_roles") or ["guest"]],
        min_radius_servers=int(nac_raw.get("min_radius_servers", 2)),
    )

    return Baseline(
        name=str(raw.get("name") or path.stem),
        version=str(raw.get("version") or "unversioned"),
        source=str(path),
        firmware=firmware,
        vlan_names=vlan_names,
        trunks=trunks,
        firewall_rules=list(rules),
        ssids=list(ssids),
        network_tags=[str(t) for t in (raw.get("scope") or {}).get("network_tags") or []],
        nac=nac,
    )


def _vlan(value: Any, path: Path, where: str) -> int:
    try:
        vid = int(value)
    except (TypeError, ValueError) as exc:
        raise BaselineError(f"{path}: {where}: {value!r} is not a VLAN ID") from exc
    if not 1 <= vid <= 4094:
        raise BaselineError(f"{path}: {where}: {vid} is outside 1-4094")
    return vid
