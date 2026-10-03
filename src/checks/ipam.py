"""Check 5 - address space reconciliation (IPAM).

Configuration says which addresses are *meant* to be used: each VLAN's
subnet, the DHCP pool inside it, the ranges carved out of that pool, and the
fixed reservations handed to specific devices. The client table says which
addresses *are* used. This check reconciles the two and reports where they
disagree, which is where address management actually breaks:

  * Subnet overlap. Two VLANs in one network with overlapping subnets
    is a routing error today (HIGH). Overlap between networks is invisible
    until the sites are joined by VPN or SD-WAN, and then it's an outage
    that can't be fixed without renumbering one of them (MEDIUM).
  * Pool exhaustion. Usable pool = subnet hosts, minus the appliance IP,
    reserved ranges and fixed reservations. Utilisation is measured against
    clients actually seen holding pool addresses: >= 90% HIGH, >= 80% MEDIUM.
  * Broken reservations. A fixed assignment outside its VLAN's subnet can
    never be served (HIGH). One whose address is held by a different device
    is a duplicate-IP incident waiting for the reserved device to come back
    (HIGH). One for a device not seen in the window is probably for hardware
    that's gone, quietly holding an address (LOW).
  * Addresses outside every declared subnet. A client using an address
    that belongs to no VLAN in its network got it from somewhere else: a
    static config left over from an old network, or a rogue DHCP server
    such as a consumer router plugged into a wall port (MEDIUM).

What this is not: a replacement for Infoblox or phpIPAM. It doesn't model
DNS, IPv6, or address space outside Meraki. It finds the specific
inconsistencies that cause outages and tickets, from data Dashboard already
has. See docs/false-positives.md for where it's wrong.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Set, Tuple

from ..scoring import CAT_IPAM, HIGH, LOW, MEDIUM, Finding, plural
from .base import CLIENT_WINDOW_DAYS, OrgContext

CHECK_NAME = "ipam"

POOL_HIGH = 0.90
POOL_MEDIUM = 0.80

RUNS_DHCP = "run a dhcp server"


def run(context: OrgContext) -> List[Finding]:
    findings: List[Finding] = []
    rows: List[Dict[str, Any]] = []
    all_subnets: List[Tuple[str, Dict[str, Any], Any]] = []  # (network, vlan, ip_network)

    for network in context.networks:
        if not context.has_product(network, "appliance"):
            continue
        net_id, net_name = network["id"], network.get("name", network["id"])
        vlans = context.appliance_vlans(net_id)
        if not vlans:
            continue
        clients = context.clients(net_id)

        parsed: List[Tuple[Dict[str, Any], Any]] = []
        for v in vlans:
            subnet = _net(v.get("subnet"))
            if subnet is None:
                context.note_limitation(
                    f"{net_name} VLAN {v.get('id')} has no parseable subnet ({v.get('subnet')!r}); skipped."
                )
                continue
            parsed.append((v, subnet))
            all_subnets.append((net_name, v, subnet))

        findings += _overlaps_within(net_name, parsed)

        # Clients by IP, for reservation and pool checks.
        by_ip: Dict[str, List[Dict[str, Any]]] = {}
        for c in clients:
            if c.get("ip"):
                by_ip.setdefault(str(c["ip"]), []).append(c)
        seen_macs = {str(c.get("mac", "")).lower() for c in clients}

        for v, subnet in parsed:
            row, vlan_findings = _reconcile_vlan(context, net_name, v, subnet, clients, by_ip, seen_macs)
            rows.append(row)
            findings += vlan_findings

        findings += _outside_every_subnet(net_name, [s for _, s in parsed], clients)

    findings += _overlaps_between(all_subnets)
    context.address_space = rows
    return findings


# ------------------------------------------------------------------ per VLAN


def _reconcile_vlan(context, net_name, v, subnet, clients, by_ip, seen_macs):
    findings: List[Finding] = []
    vid = v.get("id")
    label = f"VLAN {vid} ({v.get('name')})"
    target = f"{net_name} / {label}"
    appliance_ip = _ip(v.get("applianceIp"))
    handling = str(v.get("dhcpHandling") or "").strip()
    runs_dhcp = handling.lower() == RUNS_DHCP

    # --- reservations --------------------------------------------------------
    fixed = v.get("fixedIpAssignments") or {}
    fixed_ips: Set[Any] = set()
    for mac, entry in fixed.items():
        ip = _ip((entry or {}).get("ip"))
        name = (entry or {}).get("name") or mac
        if ip is None:
            continue
        if ip not in subnet:
            findings.append(Finding(
                category=CAT_IPAM, check=CHECK_NAME, severity=HIGH, network=net_name, target=target,
                finding=f"Fixed IP reservation '{name}' ({ip}) is outside the VLAN's subnet {subnet}.",
                evidence=(
                    f"{label} fixedIpAssignments[{mac}] = {ip} ('{name}'); subnet {subnet}."
                    + _seen_at(mac, clients)
                ),
                risk=(
                    "DHCP can only hand out addresses inside the VLAN's subnet, so this "
                    "reservation can never be served. The device takes a random lease "
                    "instead, and anything that expects it at the reserved address "
                    "(monitoring, firewall rules, a print queue) points at nothing. "
                    "It looks configured, which is why it survives."
                ),
                remediation=(
                    f"Dashboard > Security & SD-WAN > Addressing & VLANs > {label} > "
                    f"DHCP > Fixed IP assignments: correct '{name}' to an address in "
                    f"{subnet}, then update whatever references the old address."
                ),
                metadata={"mac": mac, "ip": str(ip)},
            ))
            continue
        fixed_ips.add(ip)

        holders = [c for c in by_ip.get(str(ip), []) if str(c.get("mac", "")).lower() != mac.lower()]
        if holders:
            other = holders[0]
            findings.append(Finding(
                category=CAT_IPAM, check=CHECK_NAME, severity=HIGH, network=net_name, target=target,
                finding=(
                    f"Reserved address {ip} for '{name}' is in use by a different device "
                    f"('{other.get('description') or other.get('mac')}')."
                ),
                evidence=(
                    f"{label} reserves {ip} for {mac} ('{name}'). Client "
                    f"{other.get('mac')} ('{other.get('description')}') was seen at {ip} "
                    f"in the last {CLIENT_WINDOW_DAYS} days."
                ),
                risk=(
                    "Two devices, one address. The other device is almost certainly "
                    "statically configured, because DHCP wouldn't hand out a reserved "
                    "address. When the reserved device comes back online the two will "
                    "fight over it, and both will drop intermittently in a way that "
                    "looks like a bad cable."
                ),
                remediation=(
                    f"Move '{other.get('description') or other.get('mac')}' to DHCP or to a "
                    f"documented static address outside the pool, then confirm {ip} is free."
                ),
                metadata={"mac": mac, "ip": str(ip), "holder": other.get("mac")},
            ))
        elif mac.lower() not in seen_macs:
            findings.append(Finding(
                category=CAT_IPAM, check=CHECK_NAME, severity=LOW, network=net_name, target=target,
                finding=(
                    f"Reservation '{name}' ({ip}) is for a device not seen in the last "
                    f"{CLIENT_WINDOW_DAYS} days."
                ),
                evidence=f"{label} reserves {ip} for {mac} ('{name}'); no client with that MAC in the window.",
                risk=(
                    "Usually hardware that was retired without anyone removing its "
                    "reservation. Harmless one at a time; collectively they're why pools "
                    "run out and why nobody trusts the reservation list."
                ),
                remediation=(
                    "Confirm the device is gone, then delete the reservation. If it's a "
                    "device that's only powered on occasionally, rename the reservation to "
                    "say so."
                ),
                metadata={"mac": mac, "ip": str(ip)},
            ))

    # --- pool ----------------------------------------------------------------
    hosts = _host_count(subnet)
    reserved = _reserved_addresses(v.get("reservedIpRanges") or [], subnet)
    excluded = set(reserved) | fixed_ips | ({appliance_ip} if appliance_ip in subnet else set())
    pool_size = max(hosts - len(excluded), 0)
    leased = {
        ip for ip in (_ip(c.get("ip")) for c in clients)
        if ip is not None and ip in subnet and ip not in excluded
    }
    used = len(leased)
    utilisation = (used / pool_size) if pool_size else None

    row = {
        "network": net_name, "vlan": vid, "name": v.get("name"), "subnet": str(subnet),
        "dhcp": handling or "unknown", "hosts": hosts, "reserved": len(reserved),
        "fixed": len(fixed), "pool": pool_size if runs_dhcp else None,
        "in_use": used, "utilisation": utilisation if runs_dhcp else None,
    }

    if not runs_dhcp:
        if handling:
            context.note_limitation(
                f"{net_name} {label}: DHCP is '{handling}', so pool utilisation there "
                "can't be assessed from Dashboard."
            )
        return row, findings

    if utilisation is not None and utilisation >= POOL_MEDIUM:
        severity = HIGH if utilisation >= POOL_HIGH else MEDIUM
        biggest = max(v.get("reservedIpRanges") or [{}], key=lambda r: _range_len(r, subnet), default={})
        reserved_note = (
            f" Reserved ranges remove {len(reserved)} addresses from the pool"
            + (f", including {biggest.get('start')}-{biggest.get('end')} "
               f"('{biggest.get('comment', '')}')" if biggest.get("start") else "")
            + "."
        ) if reserved else ""
        findings.append(Finding(
            category=CAT_IPAM, check=CHECK_NAME, severity=severity, network=net_name, target=target,
            finding=f"DHCP pool is {utilisation:.0%} used ({used} of {pool_size} addresses).",
            evidence=(
                f"{label} subnet {subnet}: {hosts} host addresses, minus appliance IP, "
                f"{len(reserved)} reserved and {len(fixed_ips)} fixed = {pool_size} in the pool. "
                f"{plural(used, 'distinct address', 'es')} seen in use by clients in the last "
                f"{CLIENT_WINDOW_DAYS} days.{reserved_note}"
            ),
            risk=(
                "When the pool runs out, new devices get no address and fail silently: "
                "a guest's phone shows connected with no internet, a new laptop can't "
                "reach anything. It happens at peak, which is the worst time to "
                "diagnose it."
            ),
            remediation=(
                "Reclaim before expanding: remove reserved ranges and reservations that "
                "no longer serve anything (Dashboard > Security & SD-WAN > Addressing & "
                "VLANs > DHCP), and shorten the lease time on transient networks like "
                "guest. If it's still tight, widen the subnet, which is a planned change "
                "because it touches the VLAN's gateway and firewall references."
            ),
            metadata={"pool": pool_size, "used": used, "utilisation": round(utilisation, 3)},
        ))
    return row, findings


# ------------------------------------------------------------------- overlaps


def _overlaps_within(net_name, parsed) -> List[Finding]:
    out = []
    for i, (a, sa) in enumerate(parsed):
        for b, sb in parsed[i + 1:]:
            if sa.overlaps(sb):
                out.append(Finding(
                    category=CAT_IPAM, check=CHECK_NAME, severity=HIGH, network=net_name,
                    target=f"{net_name} / VLAN {a.get('id')} & VLAN {b.get('id')}",
                    finding=f"VLAN {a.get('id')} ({sa}) and VLAN {b.get('id')} ({sb}) overlap in the same network.",
                    evidence=f"{net_name}: VLAN {a.get('id')} '{a.get('name')}' = {sa}; VLAN {b.get('id')} '{b.get('name')}' = {sb}.",
                    risk="The MX can't route to both. Hosts in the overlapping range are unreachable from one side or the other.",
                    remediation="Renumber one of the VLANs so their subnets are disjoint.",
                ))
    return out


def _overlaps_between(all_subnets) -> List[Finding]:
    out = []
    for i, (na, a, sa) in enumerate(all_subnets):
        for nb, b, sb in all_subnets[i + 1:]:
            if na == nb or not sa.overlaps(sb):
                continue
            out.append(Finding(
                category=CAT_IPAM, check=CHECK_NAME, severity=MEDIUM, network=na,
                target=f"{na} VLAN {a.get('id')} & {nb} VLAN {b.get('id')}",
                finding=f"{na} VLAN {a.get('id')} ({sa}) overlaps {nb} VLAN {b.get('id')} ({sb}).",
                evidence=(
                    f"{na}: VLAN {a.get('id')} '{a.get('name')}' = {sa}. "
                    f"{nb}: VLAN {b.get('id')} '{b.get('name')}' = {sb}."
                ),
                risk=(
                    "Harmless while the sites are separate, and a hard outage the day "
                    "they're joined by site-to-site VPN or SD-WAN: the same addresses "
                    "exist in two places and traffic can only go to one. Fixing it then "
                    "means renumbering a live site. It also makes logs, firewall rules "
                    "and any IPAM record ambiguous today."
                ),
                remediation=(
                    "Renumber the newer or smaller of the two before any VPN between "
                    "these sites, and allocate subnets from a documented per-site plan "
                    "(e.g. 10.<site>.<vlan>.0/24) so it can't recur."
                ),
            ))
    return out


def _outside_every_subnet(net_name, subnets, clients) -> List[Finding]:
    out = []
    for c in clients:
        ip = _ip(c.get("ip"))
        if ip is None or ip.is_link_local or any(ip in s for s in subnets):
            continue
        who = c.get("description") or c.get("mac")
        out.append(Finding(
            category=CAT_IPAM, check=CHECK_NAME, severity=MEDIUM, network=net_name,
            target=f"{net_name} / client '{who}'",
            finding=f"Client '{who}' is using {ip}, which belongs to no VLAN in {net_name}.",
            evidence=(
                f"Client {c.get('mac')} ('{who}') seen at {ip} on VLAN {c.get('vlan')} in the "
                f"last {CLIENT_WINDOW_DAYS} days. {net_name} subnets: "
                + ", ".join(str(s) for s in subnets) + "."
            ),
            risk=(
                "The address came from somewhere other than this network's DHCP: a "
                "static setting from an old network, or a rogue DHCP server such as a "
                "consumer router plugged into a wall port. A rogue DHCP server hands "
                "its addresses to anything nearby and bypasses the firewall's view of "
                "who is on the network."
            ),
            remediation=(
                f"Find the device ({c.get('mac')}) from its switch port in Dashboard > "
                "Network-wide > Clients. Remove any unmanaged router, and consider DHCP "
                "snooping / rogue DHCP server detection on the switches."
            ),
            metadata={"mac": c.get("mac"), "ip": str(ip)},
        ))
    return out


# -------------------------------------------------------------------- helpers


def _net(text: Any) -> Optional[Any]:
    try:
        return ipaddress.ip_network(str(text), strict=False)
    except ValueError:
        return None


def _ip(text: Any) -> Optional[Any]:
    try:
        return ipaddress.ip_address(str(text).strip()) if text else None
    except ValueError:
        return None


def _host_count(subnet) -> int:
    return max(subnet.num_addresses - 2, 0) if subnet.prefixlen < 31 else subnet.num_addresses


def _reserved_addresses(ranges, subnet) -> Set[Any]:
    out: Set[Any] = set()
    for r in ranges:
        start, end = _ip(r.get("start")), _ip(r.get("end"))
        if start is None or end is None:
            continue
        lo, hi = min(start, end), max(start, end)
        current = lo
        while current <= hi:
            if current in subnet and current not in (subnet.network_address, subnet.broadcast_address):
                out.add(current)
            current += 1
    return out


def _range_len(r, subnet) -> int:
    return len(_reserved_addresses([r], subnet)) if r else 0


def _seen_at(mac: str, clients) -> str:
    for c in clients:
        if str(c.get("mac", "")).lower() == mac.lower() and c.get("ip"):
            return f" The device is currently seen at {c['ip']} via a regular DHCP lease."
    return ""
