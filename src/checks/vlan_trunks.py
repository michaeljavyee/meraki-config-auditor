"""Check 1 - VLAN and 802.1Q trunk consistency.

This is the check the project exists for. The failure it targets is ordinary
and expensive: during a switch replacement or cutover, an uplink trunk is
rebuilt by hand, one VLAN is left out of the allowed list, and every device in
that VLAN behind the switch goes dark. The devices have power and link light,
the switch shows green in Dashboard, and nothing alerts. The first signal is
usually a person noticing the cameras have been black for a week.

Three questions, asked of every uplink trunk on every switch:

  1. Does the trunk carry every VLAN that access ports *on this switch* use?
     If not, those ports are cut off right now.                     CRITICAL
  2. Do both ends of each switch-to-switch / switch-to-MX link agree on the
     native (untagged) VLAN? If not, untagged frames change VLAN in transit.
                                                                         HIGH
  3. Does the trunk carry every VLAN the baseline requires on uplinks, and is
     its native VLAN the standard one? If not, nothing is broken yet - but the
     first device plugged into that VLAN will not work.              MEDIUM

What counts as an uplink: a trunk port whose tags or name match the baseline's
`uplink_port_tags` / `uplink_name_patterns`. Topology data is used for the
native-VLAN comparison only, because it is optional and its port naming is
inconsistent across device types (see docs/false-positives.md).
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from ..scoring import (
    CAT_VLAN_TRUNK,
    CRITICAL,
    HIGH,
    MEDIUM,
    Finding,
    VlanSet,
    format_vlans,
    plural,
)
from .base import OrgContext, product_type_of

CHECK_NAME = "vlan_trunks"


def run(context: OrgContext) -> List[Finding]:
    findings: List[Finding] = []
    trunks = context.baseline.trunks

    for network in context.networks:
        if not context.has_product(network, "switch"):
            continue
        net_id, net_name = network["id"], network.get("name", network["id"])

        # Ports already reported for a link-level native mismatch, so the
        # weaker "native differs from baseline" finding isn't stacked on top.
        native_reported = _check_link_natives(context, network, findings)

        for switch in context.devices_in(net_id, "switch"):
            serial = switch["serial"]
            switch_name = switch.get("name") or serial
            ports = context.switch_ports(serial)
            if not ports:
                context.note_limitation(
                    f"No switch port data returned for {switch_name} ({serial}) in "
                    f"{net_name}; its trunks were not assessed."
                )
                continue

            in_use = _access_vlan_usage(ports)
            uplinks = [p for p in ports if _is_uplink(p, trunks.uplink_port_tags, trunks.uplink_name_patterns)]

            if not uplinks:
                if any(p.get("type") == "trunk" for p in ports):
                    context.note_limitation(
                        f"{switch_name} in {net_name} has trunk ports but none match the "
                        "baseline's uplink tags or name patterns, so its uplink could "
                        "not be identified. Tag the uplink port 'uplink' in Dashboard."
                    )
                continue

            for uplink in uplinks:
                port_id = str(uplink.get("portId"))
                target = f"{net_name} / {switch_name} port {port_id}"
                allowed = VlanSet.parse(uplink.get("allowedVlans"))
                allowed_text = uplink.get("allowedVlans")

                # --- 1. VLANs in use downstream but not carried: outage now --
                cut_off = {vid: used for vid, used in in_use.items() if vid not in allowed}
                if cut_off:
                    findings.append(
                        _cut_off_finding(context, net_name, switch_name, serial, uplink,
                                         target, allowed_text, cut_off)
                    )

                # --- 3a. Baseline-required VLANs not carried: latent -----------
                latent = allowed.missing(set(trunks.required_vlans)) - set(cut_off)
                if latent:
                    labels = ", ".join(context.baseline.vlan_label(v) for v in sorted(latent))
                    findings.append(
                        Finding(
                            category=CAT_VLAN_TRUNK,
                            check=CHECK_NAME,
                            severity=MEDIUM,
                            network=net_name,
                            device=switch_name,
                            target=target,
                            finding=(
                                f"Uplink trunk does not carry {labels}, which the "
                                "standard requires on every uplink."
                            ),
                            evidence=(
                                f"{switch_name} ({serial}) port {port_id} "
                                f"'{uplink.get('name') or ''}': type=trunk, "
                                f"allowedVlans='{allowed_text}'. Baseline "
                                f"trunks.required_vlans = "
                                f"{format_vlans(set(trunks.required_vlans))}. No access "
                                f"port on this switch currently uses "
                                f"{format_vlans(latent)}."
                            ),
                            risk=(
                                "Nothing is broken today, which is exactly why this "
                                "survives. The first device anyone connects to this "
                                f"closet in {labels} will get link and PoE but no "
                                "network, and the person installing it will reasonably "
                                "assume the device is faulty. This is how a five-minute "
                                "install becomes a truck roll."
                            ),
                            remediation=(
                                f"Dashboard > Switching > Switch ports > {switch_name} "
                                f"port {port_id} > Allowed VLANs: add "
                                f"{format_vlans(latent)}. Make the same change on the "
                                "far end of the link so both sides match."
                            ),
                            metadata={"missing_vlans": sorted(latent)},
                        )
                    )

                # --- 3b. Native VLAN differs from the standard -----------------
                native = uplink.get("vlan")
                if (
                    trunks.native_vlan is not None
                    and native is not None
                    and int(native) != trunks.native_vlan
                    and (serial, port_id) not in native_reported
                ):
                    findings.append(
                        Finding(
                            category=CAT_VLAN_TRUNK,
                            check=CHECK_NAME,
                            severity=MEDIUM,
                            network=net_name,
                            device=switch_name,
                            target=target,
                            finding=(
                                f"Uplink trunk native VLAN is {native}; the standard "
                                f"is {trunks.native_vlan}."
                            ),
                            evidence=(
                                f"{switch_name} ({serial}) port {port_id}: native "
                                f"vlan={native}. Baseline trunks.native_vlan="
                                f"{trunks.native_vlan}."
                            ),
                            risk=(
                                "A non-standard native VLAN works only as long as the "
                                "far end was configured by the same person on the same "
                                "day. When either end is replaced and configured to "
                                "standard, untagged traffic silently changes VLAN."
                            ),
                            remediation=(
                                f"Set the native VLAN on {switch_name} port {port_id} "
                                f"to {trunks.native_vlan}, together with the far end, "
                                "in a single change window."
                            ),
                        )
                    )

    return findings


# --------------------------------------------------------------------- helpers


def _is_uplink(port: Dict[str, Any], tags: List[str], patterns: List[str]) -> bool:
    if port.get("type") != "trunk" or port.get("enabled") is False:
        return False
    port_tags = {str(t).lower() for t in port.get("tags") or []}
    if port_tags & {t.lower() for t in tags}:
        return True
    name = str(port.get("name") or "").lower()
    return any(pattern in name for pattern in patterns)


def _access_vlan_usage(ports: List[Dict[str, Any]]) -> Dict[int, List[str]]:
    """Map VLAN ID -> list of enabled access port IDs that use it.

    Voice VLANs count: a phone on a desk port tags its traffic into the voice
    VLAN, and that VLAN needs to reach the MX exactly as much as data does.
    Disabled ports don't count; they can't be cut off from anything.
    """
    usage: Dict[int, List[str]] = defaultdict(list)
    for port in ports:
        if port.get("type") != "access" or port.get("enabled") is False:
            continue
        pid = str(port.get("portId"))
        for key in ("vlan", "voiceVlan"):
            value = port.get(key)
            if value not in (None, ""):
                usage[int(value)].append(pid)
    return dict(usage)


def _cut_off_finding(
    context: OrgContext,
    net_name: str,
    switch_name: str,
    serial: str,
    uplink: Dict[str, Any],
    target: str,
    allowed_text: Any,
    cut_off: Dict[int, List[str]],
) -> Finding:
    port_id = str(uplink.get("portId"))
    vlans = sorted(cut_off)
    labels = ", ".join(context.baseline.vlan_label(v) for v in vlans)
    affected = sorted({p for ports in cut_off.values() for p in ports}, key=_port_sort_key)
    per_vlan = "; ".join(
        f"VLAN {v}: access ports {', '.join(sorted(cut_off[v], key=_port_sort_key))}"
        for v in vlans
    )
    return Finding(
        category=CAT_VLAN_TRUNK,
        check=CHECK_NAME,
        severity=CRITICAL,
        network=net_name,
        device=switch_name,
        target=target,
        finding=(
            f"{labels} is in use on {plural(len(affected), 'access port')} but is not "
            "carried on the switch's uplink trunk. Those ports have no path off the "
            "switch."
        ),
        evidence=(
            f"{switch_name} ({serial}) uplink port {port_id} "
            f"'{uplink.get('name') or ''}': type=trunk, allowedVlans='{allowed_text}'. "
            f"Missing from the allowed list but assigned locally - {per_vlan}."
        ),
        risk=(
            f"Every device on those {len(affected)} ports is offline right now. They "
            "still have link and PoE, and the switch reports healthy in Dashboard, so "
            "nothing alerts: the failure is only visible from the device's side. This "
            "is the classic post-cutover outage - an uplink trunk rebuilt by hand with "
            "one VLAN left off - and it is typically discovered days later by someone "
            "who needed the device."
        ),
        remediation=(
            f"Dashboard > Switching > Switch ports > {switch_name} port {port_id} > "
            f"Allowed VLANs: add {format_vlans(set(vlans))}, then confirm the far end of "
            "the link allows it too. Afterwards, add the baseline's required VLAN list "
            "to the cutover checklist and run this audit before closing any switch "
            "replacement change."
        ),
        metadata={"vlans": vlans, "affected_ports": affected},
    )


def _check_link_natives(
    context: OrgContext, network: Dict[str, Any], findings: List[Finding]
) -> Set[Tuple[str, str]]:
    """Compare native VLANs across both ends of each discovered link.

    Returns the (serial, portId) pairs that were reported, for de-duplication.
    """
    reported: Set[Tuple[str, str]] = set()
    net_id, net_name = network["id"], network.get("name", network["id"])
    topology = context.link_layer(net_id)
    if not topology:
        context.note_limitation(
            f"Link-layer topology was unavailable for {net_name}, so native VLANs "
            "were compared against the baseline only, not between link ends."
        )
        return reported

    for link in topology.get("links") or []:
        ends = link.get("ends") or []
        if len(ends) != 2:
            continue
        resolved = [_resolve_end(context, net_id, end) for end in ends]
        if any(r is None for r in resolved):
            continue
        (a_serial, a_port, a_native), (b_serial, b_port, b_native) = resolved  # type: ignore[misc]
        if a_native is None or b_native is None or int(a_native) == int(b_native):
            continue

        a_name, b_name = context.device_name(a_serial), context.device_name(b_serial)
        reported.update({(a_serial, a_port), (b_serial, b_port)})
        findings.append(
            Finding(
                category=CAT_VLAN_TRUNK,
                check=CHECK_NAME,
                severity=HIGH,
                network=net_name,
                device=f"{a_name} <-> {b_name}",
                target=f"{net_name} / {a_name}:{a_port} <-> {b_name}:{b_port}",
                finding=(
                    f"Native VLAN mismatch across one link: {a_name} port {a_port} "
                    f"uses native VLAN {a_native}, {b_name} port {b_port} uses "
                    f"{b_native}."
                ),
                evidence=(
                    f"Link-layer topology pairs {a_name} ({a_serial}) port {a_port} "
                    f"with {b_name} ({b_serial}) port {b_port}. Native VLAN: "
                    f"{a_name}={a_native}, {b_name}={b_native}."
                ),
                risk=(
                    "Untagged frames leave one switch in one VLAN and arrive at the "
                    "other in a different one. Anything that relies on the native "
                    "VLAN - management traffic, devices on untagged ports downstream "
                    "- ends up in the wrong segment. Besides intermittent "
                    "connectivity problems that are very hard to diagnose, it is a "
                    "segmentation leak: traffic crosses between VLANs without going "
                    "through the firewall."
                ),
                remediation=(
                    "Pick the standard native VLAN"
                    + (f" ({context.baseline.trunks.native_vlan})" if context.baseline.trunks.native_vlan else "")
                    + f" and set it on both {a_name} port {a_port} and {b_name} port "
                    f"{b_port} in the same change window. Changing one end alone moves "
                    "the problem rather than fixing it."
                ),
                metadata={"ends": [[a_serial, a_port, a_native], [b_serial, b_port, b_native]]},
            )
        )
    return reported


def _resolve_end(
    context: OrgContext, network_id: str, end: Dict[str, Any]
) -> Optional[Tuple[str, str, Optional[int]]]:
    """Turn one topology link end into (serial, portId, native VLAN)."""
    serial = ((end.get("device") or {}).get("serial")) or ""
    device = context.devices_by_serial.get(serial)
    if not device:
        return None
    discovered = end.get("discovered") or {}
    raw_port = ((discovered.get("lldp") or {}).get("portId")
                or (discovered.get("cdp") or {}).get("portId"))
    port_id = _normalise_port_id(raw_port)
    if not port_id:
        return None

    product = product_type_of(device)
    if product == "switch":
        for port in context.switch_ports(serial):
            if str(port.get("portId")) == port_id:
                return serial, port_id, port.get("vlan")
    elif product == "appliance":
        for port in context.appliance_ports(network_id):
            if str(port.get("number")) == port_id:
                return serial, port_id, port.get("vlan")
    return None


def _normalise_port_id(raw: Any) -> str:
    """LLDP/CDP report ports as "8", "Port 8" or "GigabitEthernet1/0/8"."""
    if raw is None:
        return ""
    match = re.search(r"(\d+)\s*$", str(raw))
    return match.group(1) if match else ""


def _port_sort_key(port_id: str) -> Tuple[int, str]:
    return (int(port_id), "") if port_id.isdigit() else (10**6, port_id)
