"""Live configuration, normalised into the same shape an intent file uses.

This is the read half of config-as-code. `export` writes it out as YAML, and
`plan` compares it with a declared intent. Both go through `read_network`, so
the shape that `export` produces is, by construction, the shape `plan`
understands: export a network, plan against the export, and the plan is empty.
There is a test for exactly that.

Only the attributes listed in MANAGED_ATTRS are read. That list is the
contract for what this tool can describe as code. Anything Dashboard returns
outside it (port status, client counts, PoE draw) is state, not configuration,
and has no place in a file that describes intent.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .checks.base import OrgContext

# Resource kinds and the attributes of each that intent can declare.
MANAGED_ATTRS: Dict[str, List[str]] = {
    "appliance_vlans": ["name", "subnet", "applianceIp"],
    "switch_ports": [
        "name", "enabled", "type", "vlan", "voiceVlan", "allowedVlans", "tags",
        "poeEnabled", "rstpEnabled", "stpGuard", "accessPolicyType", "accessPolicyNumber",
    ],
    "ssids": [
        "name", "enabled", "authMode", "encryptionMode", "wpaEncryptionMode",
        "ipAssignmentMode", "useVlanTagging", "defaultVlanId", "bandSelection",
        "minBitrate", "visible",
    ],
}

# Firewall rules are one ordered list, not keyed items: order is behaviour.
L3_RULE_ATTRS = [
    "comment", "policy", "protocol", "srcCidr", "srcPort", "destCidr", "destPort", "syslogEnabled",
]

KINDS = ["appliance_vlans", "l3_firewall_rules", "switch_ports", "ssids"]


def read_network(context: OrgContext, network: Dict[str, Any]) -> Dict[str, Any]:
    """Return one network's configuration in intent shape.

    {
      "appliance_vlans":   {vlan_id: {attr: value}},
      "l3_firewall_rules": [ {rule}, ... ]          (default rule excluded)
      "switch_ports":      {switch_name: {port_id: {attr: value}}},
      "ssids":             {number: {attr: value}},
    }

    Sections a network doesn't have (no MX, no switches) are omitted rather
    than written as empty, so an export doesn't claim to manage them.
    """
    net_id = network["id"]
    out: Dict[str, Any] = {}

    if context.has_product(network, "appliance"):
        vlans = context.appliance_vlans(net_id)
        if vlans:
            out["appliance_vlans"] = {
                int(v["id"]): _pick(v, MANAGED_ATTRS["appliance_vlans"]) for v in vlans
            }
        rules = context.l3_firewall_rules(net_id)
        if rules is not None:
            out["l3_firewall_rules"] = [
                _pick(r, L3_RULE_ATTRS) for r in strip_default_rule(rules)
            ]

    if context.has_product(network, "switch"):
        switches: Dict[str, Dict[str, Any]] = {}
        for switch in context.devices_in(net_id, "switch"):
            ports = context.switch_ports(switch["serial"])
            if ports:
                switches[switch_key(switch)] = {
                    str(p["portId"]): _pick(p, MANAGED_ATTRS["switch_ports"]) for p in ports
                }
        if switches:
            out["switch_ports"] = switches

    if context.has_product(network, "wireless"):
        ssids = {
            int(s["number"]): _pick(s, MANAGED_ATTRS["ssids"])
            for s in context.ssids(net_id)
            if is_configured_ssid(s)
        }
        if ssids:
            out["ssids"] = ssids

    return out


def switch_key(device: Dict[str, Any]) -> str:
    """Name when it has one (readable in a diff), serial otherwise."""
    return device.get("name") or device["serial"]


def find_switch(context: OrgContext, network_id: str, key: str) -> Optional[Dict[str, Any]]:
    """Resolve an intent switch key (name or serial) to a device in the network."""
    for device in context.devices_in(network_id, "switch"):
        if key in (device.get("name"), device.get("serial")):
            return device
    return None


def is_configured_ssid(ssid: Dict[str, Any]) -> bool:
    """Dashboard always returns all 15 SSID slots. Untouched ones aren't intent."""
    if ssid.get("enabled"):
        return True
    return not str(ssid.get("name", "")).startswith("Unconfigured SSID")


def strip_default_rule(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop the implicit trailing default rule; it isn't configurable."""
    if rules and str(rules[-1].get("comment", "")).strip().lower() == "default rule":
        return list(rules[:-1])
    return list(rules)


def _pick(item: Dict[str, Any], attrs: List[str]) -> Dict[str, Any]:
    return {a: item.get(a) for a in attrs if a in item}
