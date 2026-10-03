"""Check 6 - 802.1X / NAC posture.

802.1X is easy to have and hard to have *working*. The access policy exists,
the ports are assigned to it, the dashboard says "802.1X", and the network is
still open in ways nobody wrote down. This check looks for those ways from
three angles.

**Policy design** (from GET /networks/{id}/switch/accessPolicies):

  * Multi-Host mode: the first device on a port authenticates and the port
    opens to every device behind it, so a small unmanaged switch turns one
    login into unlimited access.                                       HIGH
  * A guest or failed-auth VLAN that isn't a guest VLAN: failing 802.1X
    lands the client somewhere privileged.                              HIGH
  * Critical-auth (fail-open) into a data VLAN: when RADIUS is unreachable,
    every port admits everyone. Often a deliberate availability trade-off,
    so it's reported to be written down, not as an error.             MEDIUM
  * Fewer RADIUS servers than the standard requires: one server outage is a
    site-wide authentication outage.                                  MEDIUM
  * MAB-only policies, and RADIUS accounting off.               MEDIUM / LOW

**Coverage** (from switch port configuration): enabled access ports that
don't enforce any access policy and aren't tagged as exempt. A site with no
enforcing ports at all is one HIGH finding rather than one per port.

**Outcomes** (from GET /networks/{id}/clients, wired clients only): how each
client on an enforcing port actually got on. Dashboard records the 802.1X
identity in the client's `user` field; a wired client on an enforcing port
with no identity came in through MAB, and one in the guest/failed-auth VLAN
failed. Two outcomes are findings:

  * A general-purpose computer (Windows, macOS, Linux, ChromeOS) admitted by
    MAB: its supplicant isn't working and its MAC was allow-listed instead.
    Anyone who copies that MAC gets the same access.                    HIGH
  * A client sitting in the guest/failed-auth VLAN on a desk port: failing
    authentication quietly, which is a ticket nobody has raised yet. MEDIUM

Phones, printers and other headless devices on MAB are expected and only
counted. The posture table in the report shows the full breakdown per switch.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from ..scoring import CAT_NAC, HIGH, LOW, MEDIUM, Finding, plural
from .base import CLIENT_WINDOW_DAYS, OrgContext

CHECK_NAME = "nac"

ENFORCING_PORT_TYPES = {"custom access policy", "mac allow list", "sticky mac allow list"}
GENERAL_PURPOSE_OS = ("windows", "mac", "linux", "chrome", "ubuntu")
MAB_ONLY = "mac authentication bypass"


def run(context: OrgContext) -> List[Finding]:
    findings: List[Finding] = []
    nac = context.baseline.nac
    guest_vlans = {
        vid for vid, role in context.baseline.vlan_names.items()
        if role.lower() in nac.guest_vlan_roles
    }

    for network in context.networks:
        if not context.has_product(network, "switch"):
            continue
        net_id = network["id"]
        net_name = network.get("name", net_id)
        policies = {str(p.get("accessPolicyNumber")): p for p in context.access_policies(net_id)}

        for policy in policies.values():
            findings += _policy_findings(context, net_name, policy, guest_vlans, nac.min_radius_servers)

        clients = [c for c in context.clients(net_id) if c.get("recentDeviceSerial") and c.get("switchport")]
        gaps_by_switch: Dict[str, List[Dict[str, Any]]] = {}
        enforcing_total = 0

        for switch in context.devices_in(net_id, "switch"):
            serial = switch["serial"]
            name = switch.get("name") or serial
            row = {"network": net_name, "switch": name, "access_ports": 0, "enforcing": 0,
                   "exempt": 0, "open": 0, "dot1x": 0, "mab": 0, "failed": 0, "on_open": 0}
            port_policy: Dict[str, Optional[Dict[str, Any]]] = {}

            for port in context.switch_ports(serial):
                if port.get("type") != "access" or port.get("enabled") is False:
                    continue
                pid = str(port.get("portId"))
                row["access_ports"] += 1
                kind = str(port.get("accessPolicyType") or "Open").lower()
                if kind in ENFORCING_PORT_TYPES:
                    row["enforcing"] += 1
                    enforcing_total += 1
                    policy = policies.get(str(port.get("accessPolicyNumber"))) if kind == "custom access policy" else None
                    if kind == "custom access policy" and policy is None:
                        findings.append(_missing_policy(net_name, name, pid, port))
                    port_policy[pid] = policy
                    continue
                tags = {str(t).lower() for t in port.get("tags") or []}
                if tags & set(nac.exempt_port_tags):
                    row["exempt"] += 1
                    continue
                row["open"] += 1
                port_policy[pid] = None
                gaps_by_switch.setdefault(name, []).append(port)

            for c in (c for c in clients if c.get("recentDeviceSerial") == serial):
                pid = str(c.get("switchport"))
                if pid not in port_policy:
                    continue
                policy = port_policy[pid]
                if policy is None:
                    row["on_open"] += 1
                    continue
                outcome = _outcome(c, policy)
                row[outcome] += 1
                f = _outcome_finding(context, net_name, name, pid, c, policy, outcome)
                if f:
                    findings.append(f)

            if row["access_ports"]:
                context.nac_posture.append(row)

        if nac.required and gaps_by_switch:
            findings += _coverage_findings(net_name, gaps_by_switch, enforcing_total)

        if policies and not clients:
            context.note_limitation(
                f"No wired client data with switch port attribution for {net_name}; "
                "802.1X outcomes there are based on configuration only."
            )

    return findings


# ------------------------------------------------------------------- policy


def _policy_findings(context, net_name, policy, guest_vlans, min_servers) -> List[Finding]:
    out: List[Finding] = []
    pname = policy.get("name") or f"policy {policy.get('accessPolicyNumber')}"
    target = f"{net_name} / access policy '{pname}'"
    base = dict(category=CAT_NAC, check=CHECK_NAME, network=net_name, target=target)
    label = context.baseline.vlan_label
    radius = policy.get("radius") or {}
    path = (f"Dashboard > Switching > Access policies > {pname}")

    if str(policy.get("hostMode", "")).lower() == "multi-host":
        out.append(Finding(severity=HIGH, **base,
            finding=f"Access policy '{pname}' uses Multi-Host mode.",
            evidence=f"accessPolicies[{policy.get('accessPolicyNumber')}]: hostMode='Multi-Host', type='{policy.get('accessPolicyType')}'.",
            risk=("In Multi-Host mode the switch authenticates the first device on a port and then "
                  "admits every device behind it without asking. An unmanaged switch or a hub under "
                  "a desk turns one valid login into unlimited access for anything plugged into it. "
                  "It's usually set this way to make exactly that kind of desk work."),
            remediation=(f"{path}: change host mode to Multi-Auth (each device authenticates) or "
                         "Multi-Domain (one data + one voice device). Replace the unmanaged switch "
                         "under the desk with a port per device, or a managed switch."),
        ))

    for field_name, value in (("guestVlanId", policy.get("guestVlanId")),
                              ("radius.failedAuthVlanId", radius.get("failedAuthVlanId"))):
        if value in (None, "") or int(value) in guest_vlans:
            continue
        out.append(Finding(severity=HIGH, **base,
            finding=f"Clients that fail 802.1X in '{pname}' are placed in {label(int(value))}, which isn't a guest VLAN.",
            evidence=(f"accessPolicies[{policy.get('accessPolicyNumber')}].{field_name} = {value}. "
                      f"Baseline guest VLANs: {', '.join(str(v) for v in sorted(guest_vlans)) or 'none'}."),
            risk=("Failing authentication is supposed to end somewhere harmless. Here it ends in a "
                  "privileged network, so the simplest way past 802.1X is to fail it."),
            remediation=f"{path}: set the guest / failed-authentication VLAN to the guest VLAN.",
        ))

    crit = (radius.get("criticalAuth") or {}).get("dataVlanId")
    if crit not in (None, ""):
        out.append(Finding(severity=MEDIUM, **base,
            finding=f"'{pname}' fails open into {label(int(crit))} when RADIUS is unreachable.",
            evidence=(f"accessPolicies[{policy.get('accessPolicyNumber')}].radius.criticalAuth.dataVlanId = {crit}. "
                      f"RADIUS servers: {', '.join(s.get('host', '?') for s in policy.get('radiusServers') or []) or 'none'}."),
            risk=("If the RADIUS servers can't be reached, every port on this policy admits every "
                  "device into that VLAN. That keeps desks working during an outage, which is a "
                  "reasonable choice, and it also means anyone who can disrupt RADIUS disables "
                  "802.1X. It should be a written decision with monitoring on RADIUS reachability, "
                  "not a default nobody remembers setting."),
            remediation=("Either record the fail-open decision and alert on RADIUS reachability, or "
                         f"point critical auth at a restricted VLAN instead: {path} > Critical authentication."),
        ))

    servers = policy.get("radiusServers") or []
    if len(servers) < min_servers:
        out.append(Finding(severity=MEDIUM, **base,
            finding=f"'{pname}' has {plural(len(servers), 'RADIUS server')}; the standard is at least {min_servers}.",
            evidence=f"radiusServers: {', '.join(s.get('host', '?') for s in servers) or 'none'}.",
            risk=("A single RADIUS server is a single point of failure for every port on this "
                  "policy. When it's patched, rebooted or unreachable, either nobody can "
                  "authenticate or (with fail-open) everybody can."),
            remediation=f"{path}: add a second RADIUS server, ideally at a different site.",
        ))

    if str(policy.get("accessPolicyType", "")).lower() == MAB_ONLY:
        out.append(Finding(severity=MEDIUM, **base,
            finding=f"'{pname}' authenticates by MAC address only.",
            evidence=f"accessPolicies[{policy.get('accessPolicyNumber')}].accessPolicyType = 'MAC authentication bypass'.",
            risk=("A MAC address is an identifier, not a credential: it's printed on the device and "
                  "visible to anything on the same port. MAB-only is appropriate for headless "
                  "devices on an isolated VLAN, and nowhere else."),
            remediation="Use Hybrid authentication so devices that can do 802.1X must, and keep MAB for headless devices.",
        ))

    if policy.get("radiusAccountingEnabled") is False:
        out.append(Finding(severity=LOW, **base,
            finding=f"RADIUS accounting is off for '{pname}'.",
            evidence=f"accessPolicies[{policy.get('accessPolicyNumber')}].radiusAccountingEnabled = false.",
            risk=("Without accounting, the RADIUS server knows who authenticated but not for how long "
                  "or from which port, which is the record an incident investigation needs."),
            remediation=f"{path}: enable RADIUS accounting.",
        ))
    return out


def _missing_policy(net_name, switch_name, pid, port) -> Finding:
    return Finding(category=CAT_NAC, check=CHECK_NAME, severity=HIGH, network=net_name,
        target=f"{net_name} / {switch_name} port {pid}",
        finding=f"Port {pid} references access policy {port.get('accessPolicyNumber')}, which doesn't exist.",
        evidence=f"{switch_name} port {pid}: accessPolicyType='Custom access policy', accessPolicyNumber={port.get('accessPolicyNumber')!r}.",
        risk="The port's intended policy can't be determined, so whether it enforces anything is unknown.",
        remediation="Reassign the port to an existing access policy.",
    )


# ----------------------------------------------------------------- coverage


def _coverage_findings(net_name, gaps_by_switch, enforcing_total) -> List[Finding]:
    total = sum(len(p) for p in gaps_by_switch.values())
    detail = "; ".join(
        f"{switch}: " + ", ".join(f"{p.get('portId')} '{p.get('name') or ''}'".strip() for p in ports)
        for switch, ports in sorted(gaps_by_switch.items())
    )
    risk = ("Anything plugged into these ports is on the network with no identity check: a "
            "visitor's laptop, a contractor's device, or a consumer router handing out its own "
            "addresses. Network access is then controlled by who can reach a wall jack.")
    if enforcing_total == 0:
        return [Finding(category=CAT_NAC, check=CHECK_NAME, severity=HIGH, network=net_name,
            target=f"{net_name} / all access ports",
            finding=f"No access port at {net_name} enforces 802.1X or any access policy.",
            evidence=f"{plural(total, 'enabled access port')} without an access policy or exempt tag. {detail}.",
            risk=risk + " Here that's true of the whole site.",
            remediation=("Create an access policy for the site (Dashboard > Switching > Access policies), "
                         "assign it to user-facing ports, and tag ports that are deliberately exempt "
                         "(cameras, kiosks) so the exemption is visible."),
        )]
    out = []
    for switch, ports in sorted(gaps_by_switch.items()):
        ids = ", ".join(str(p.get("portId")) for p in ports)
        out.append(Finding(category=CAT_NAC, check=CHECK_NAME, severity=MEDIUM, network=net_name,
            target=f"{net_name} / {switch}",
            finding=(f"{plural(len(ports), 'access port')} on {switch} "
                     f"{'enforces' if len(ports) == 1 else 'enforce'} no access policy ({ids})."),
            evidence="; ".join(f"port {p.get('portId')} '{p.get('name') or ''}': accessPolicyType='Open', VLAN {p.get('vlan')}" for p in ports) + ".",
            risk=risk,
            remediation=(f"Assign the site's access policy to these ports on {switch}, or tag them "
                         "'nac-exempt' with a note on why."),
        ))
    return out


# ----------------------------------------------------------------- outcomes


def _outcome(client: Dict[str, Any], policy: Optional[Dict[str, Any]]) -> str:
    if client.get("user"):
        return "dot1x"
    fallback = _fallback_vlans(policy)
    if client.get("vlan") not in (None, "") and int(client["vlan"]) in fallback:
        return "failed"
    return "mab"


def _fallback_vlans(policy: Optional[Dict[str, Any]]) -> Set[int]:
    if not policy:
        return set()
    radius = policy.get("radius") or {}
    return {int(v) for v in (policy.get("guestVlanId"), radius.get("failedAuthVlanId")) if v not in (None, "")}


def _outcome_finding(context, net_name, switch, pid, client, policy, outcome) -> Optional[Finding]:
    who = client.get("description") or client.get("mac")
    os_name = str(client.get("os") or "")
    pname = (policy or {}).get("name") or "access policy"
    if outcome == "mab" and any(k in os_name.lower() for k in GENERAL_PURPOSE_OS):
        return Finding(category=CAT_NAC, check=CHECK_NAME, severity=HIGH, network=net_name,
            target=f"{net_name} / {switch} port {pid}",
            finding=f"'{who}' ({os_name}) got onto VLAN {client.get('vlan')} by MAC address, not 802.1X.",
            evidence=(f"Client {client.get('mac')} '{who}', os='{os_name}', on {switch} port {pid} "
                      f"('{pname}', {policy.get('accessPolicyType')}) in VLAN {client.get('vlan')} with no "
                      f"802.1X identity recorded in the last {CLIENT_WINDOW_DAYS} days."),
            risk=("A general-purpose computer should authenticate with its own credentials. One that "
                  "got in by MAC address almost always has a broken or disabled supplicant, and its "
                  "MAC was added to the RADIUS allow list to close the ticket. Anyone who reads that "
                  "MAC off the device and sets it on their own gets the same access."),
            remediation=(f"Fix the supplicant on '{who}' so it authenticates with 802.1X, then remove "
                         "its MAC from the MAB allow list on the RADIUS server."),
            metadata={"mac": client.get("mac")},
        )
    if outcome == "failed":
        return Finding(category=CAT_NAC, check=CHECK_NAME, severity=MEDIUM, network=net_name,
            target=f"{net_name} / {switch} port {pid}",
            finding=f"'{who}' is failing 802.1X on a desk port and landing in {context.baseline.vlan_label(int(client['vlan']))}.",
            evidence=(f"Client {client.get('mac')} '{who}', os='{os_name or 'unknown'}', on {switch} port {pid} "
                      f"('{pname}') in VLAN {client.get('vlan')}, the policy's guest / failed-auth VLAN."),
            risk=("The policy is doing its job, and someone is quietly working on the guest network "
                  "from a desk. It's an expired certificate, an unenrolled device or an unauthorised "
                  "one, and today nobody would know which."),
            remediation=(f"Identify the owner of {client.get('mac')}; enrol the device or remove it. "
                         "Consider alerting on failed-auth VLAN assignments."),
            metadata={"mac": client.get("mac")},
        )
    return None
