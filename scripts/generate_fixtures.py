"""Generate the synthetic demo organization served by `--demo`.

    python scripts/generate_fixtures.py

The organization is fictional: "Cedar Valley Logistics", a three-site company
(HQ plus two vehicle depots). Every name, serial, MAC, subnet and ID below is
invented. No employer or customer data is used anywhere in this repository.

The fixtures are generated from code rather than hand-written JSON so that the
*story* in each site is readable in one place:

  HQ          - the reference site. Close to the baseline, with one latent gap.
  Depot-East  - drifted slowly over two years of small changes.
  Depot-West  - cut over to new switching in September 2026. The IDF switch was
                swapped, its uplink trunk was rebuilt by hand, and the camera
                VLAN didn't make it onto the trunk. The yard cameras have been
                offline since. This is the failure the tool exists to catch
                *before* a cutover rather than after it.

Response shapes follow the Meraki Dashboard API v1 documentation. Where the
real API returns more fields than the checks read, the fixtures include a
representative subset rather than every field.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

OUT = Path(__file__).resolve().parent.parent / "src" / "fixtures"

ORG_ID = "100000"
NET_HQ = "L_100000000000000001"
NET_EAST = "L_100000000000000002"
NET_WEST = "L_100000000000000003"


def write(name: str, data: Any) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n")


# --------------------------------------------------------------- organization

organizations = [
    {
        "id": ORG_ID,
        "name": "Cedar Valley Logistics",
        "url": "https://n000.meraki.com/o/EXAMPLE/manage/organization/overview",
        "api": {"enabled": True},
    }
]

networks = [
    {
        "id": NET_HQ,
        "organizationId": ORG_ID,
        "name": "HQ",
        "productTypes": ["appliance", "camera", "switch", "wireless"],
        "timeZone": "America/Los_Angeles",
        "tags": ["hq"],
    },
    {
        "id": NET_EAST,
        "organizationId": ORG_ID,
        "name": "Depot-East",
        "productTypes": ["appliance", "camera", "switch", "wireless"],
        "timeZone": "America/Los_Angeles",
        "tags": ["depot"],
    },
    {
        "id": NET_WEST,
        "organizationId": ORG_ID,
        "name": "Depot-West",
        "productTypes": ["appliance", "camera", "switch", "wireless"],
        "timeZone": "America/Los_Angeles",
        "tags": ["depot", "cutover-2026-09"],
    },
]


# -------------------------------------------------------------------- devices

def _fake_mac(serial: str) -> str:
    """Deterministic, obviously-synthetic MAC derived from the serial."""
    digest = hashlib.sha256(serial.encode()).hexdigest()
    return "00:18:0a:" + ":".join(digest[i:i + 2] for i in (0, 2, 4))


def device(name, serial, model, net, product, firmware, ip, tags=None):
    return {
        "name": name,
        "serial": serial,
        "mac": _fake_mac(serial),
        "networkId": net,
        "model": model,
        "productType": product,
        "firmware": firmware,
        "lanIp": ip,
        "tags": tags or [],
    }


devices = [
    # HQ
    device("MX-HQ", "Q2XX-HQ00-MX01", "MX85", NET_HQ, "appliance", "wired-18-2-11", "10.10.1.1"),
    device("SW-HQ-CORE", "Q2XX-HQ00-SW01", "MS250-48LP", NET_HQ, "switch", "switch-17-1-4", "10.10.1.2"),
    device("SW-HQ-IDF1", "Q2XX-HQ00-SW02", "MS130-24P", NET_HQ, "switch", "switch-17-1-4", "10.10.1.3"),
    device("AP-HQ-01", "Q2XX-HQ00-AP01", "MR46", NET_HQ, "wireless", "wireless-30-7", "10.10.1.21"),
    device("AP-HQ-02", "Q2XX-HQ00-AP02", "MR46", NET_HQ, "wireless", "wireless-30-7", "10.10.1.22"),
    device("CAM-HQ-LOBBY", "Q2XX-HQ00-CM01", "MV63", NET_HQ, "camera", "camera-5-3", "10.10.40.11"),
    # Depot-East
    device("MX-EAST", "Q2XX-EA00-MX01", "MX67", NET_EAST, "appliance", "wired-18-2-11", "10.20.1.1"),
    device("SW-EAST-CORE", "Q2XX-EA00-SW01", "MS130-24P", NET_EAST, "switch", "switch-17-1-4", "10.20.1.2"),
    device("SW-EAST-IDF1", "Q2XX-EA00-SW02", "MS130-8P", NET_EAST, "switch", "switch-17-1-4", "10.20.1.3"),
    device("AP-EAST-01", "Q2XX-EA00-AP01", "MR36", NET_EAST, "wireless", "wireless-31-1", "10.20.1.21",
           tags=["beta-test"]),
    device("CAM-EAST-GATE", "Q2XX-EA00-CM01", "MV63", NET_EAST, "camera", "camera-5-3", "10.20.40.11"),
    # Depot-West
    device("MX-WEST", "Q2XX-WE00-MX01", "MX67", NET_WEST, "appliance", "wired-18-1-7", "10.30.1.1"),
    device("SW-WEST-CORE", "Q2XX-WE00-SW01", "MS130-24P", NET_WEST, "switch", "switch-17-1-4", "10.30.1.2"),
    device("SW-WEST-IDF1", "Q2XX-WE00-SW03", "MS130-8P", NET_WEST, "switch", "switch-16-8-1", "10.30.1.3",
           tags=["replaced-2026-09"]),
    device("AP-WEST-01", "Q2XX-WE00-AP01", "MR36", NET_WEST, "wireless", "wireless-30-7", "10.30.1.21"),
    device("CAM-WEST-YARD-01", "Q2XX-WE00-CM01", "MV63", NET_WEST, "camera", "camera-5-3", "10.30.40.11"),
    device("CAM-WEST-YARD-02", "Q2XX-WE00-CM02", "MV63", NET_WEST, "camera", "camera-5-3", "10.30.40.12"),
]


# --------------------------------------------------------------- switch ports

def port(
    port_id: int,
    name: str,
    *,
    type: str = "access",
    vlan: int = 10,
    allowed: str = "all",
    voice: Optional[int] = None,
    tags: Optional[List[str]] = None,
    enabled: bool = True,
    policy: Optional[int] = None,
) -> Dict[str, Any]:
    access = (
        {"accessPolicyType": "Custom access policy", "accessPolicyNumber": policy}
        if policy is not None else {"accessPolicyType": "Open"}
    )
    return {
        "portId": str(port_id),
        "name": name,
        "tags": tags or [],
        "enabled": enabled,
        "poeEnabled": type == "access",
        "type": type,
        "vlan": vlan,
        "voiceVlan": voice,
        "allowedVlans": allowed if type == "trunk" else "all",
        "rstpEnabled": True,
        "stpGuard": "disabled" if type == "trunk" else "bpdu guard",
        **access,
    }


switch_ports = {
    # HQ ---------------------------------------------------------------------
    "Q2XX-HQ00-SW01": [
        *[port(i, f"Desk {i}", vlan=10, voice=20, policy=1) for i in range(1, 5)],
        port(5, "Lobby camera", vlan=40, tags=["camera"]),
        port(47, "Downlink SW-HQ-IDF1", type="trunk", vlan=1, allowed="all", tags=["downlink"]),
        port(48, "Uplink MX-HQ", type="trunk", vlan=1, allowed="1,10,20,30,40", tags=["uplink"]),
    ],
    # Latent gap: VLAN 40 is in the baseline but no camera is attached here
    # yet. Nothing is broken today; the day someone plugs a camera into this
    # IDF it won't come up.
    "Q2XX-HQ00-SW02": [
        *[port(i, f"Desk {i}", vlan=10, voice=20, policy=1) for i in range(1, 5)],
        port(5, "Guest kiosk", vlan=30, tags=["nac-exempt"]),
        port(24, "Uplink SW-HQ-CORE", type="trunk", vlan=1, allowed="1,10,20,30", tags=["uplink"]),
    ],
    # Depot-East -------------------------------------------------------------
    "Q2XX-EA00-SW01": [
        *[port(i, f"Dispatch {i}", vlan=10, voice=20, policy=1) for i in range(1, 4)],
        port(23, "Downlink SW-EAST-IDF1", type="trunk", vlan=1, allowed="all", tags=["downlink"]),
        port(24, "Uplink MX-EAST", type="trunk", vlan=1, allowed="1,10,20,30,40", tags=["uplink"]),
    ],
    # Native VLAN mismatch: this end of the core<->IDF link was set to native
    # 10 at some point; the core end is still native 1. Untagged traffic
    # (including some management protocols) lands in different VLANs at each
    # end of the same cable.
    "Q2XX-EA00-SW02": [
        port(1, "Gate camera", vlan=40, tags=["camera"]),
        port(2, "Fuel island camera", vlan=40, tags=["camera"]),
        port(3, "Shop PC", vlan=10),
        port(8, "Uplink SW-EAST-CORE", type="trunk", vlan=10, allowed="1,10,20,30,40", tags=["uplink"]),
    ],
    # Depot-West -------------------------------------------------------------
    "Q2XX-WE00-SW01": [
        *[port(i, f"Dispatch {i}", vlan=10, voice=20) for i in range(1, 3)],
        port(23, "Downlink SW-WEST-IDF1", type="trunk", vlan=1, allowed="all", tags=["downlink"]),
        port(24, "Uplink MX-WEST", type="trunk", vlan=1, allowed="1,10,20,30,40", tags=["uplink"]),
    ],
    # THE FLAGSHIP FAILURE. Replacement IDF switch, uplink trunk rebuilt by
    # hand during the cutover. Five yard cameras sit in VLAN 40 on this switch,
    # and VLAN 40 is not in the uplink's allowed list. The cameras have power
    # and link light and no path to anything.
    "Q2XX-WE00-SW03": [
        *[port(i, f"Yard camera {i}", vlan=40, tags=["camera"]) for i in range(1, 6)],
        port(6, "Wash bay PC", vlan=10),
        port(7, "Spare", vlan=10, enabled=False),
        port(8, "Uplink", type="trunk", vlan=1, allowed="1,10,20,30", tags=["uplink"]),
    ],
}


# ------------------------------------------------------------- appliance side

def site_vlans(net: str, octet: int) -> List[Dict[str, Any]]:
    names = {1: "Management", 10: "Corp", 20: "Voice", 30: "Guest", 40: "Cameras"}
    return [
        {
            "id": vid,
            "networkId": net,
            "name": name,
            "applianceIp": f"10.{octet}.{vid}.1",
            "subnet": f"10.{octet}.{vid}.0/24",
            "dhcpHandling": "Run a DHCP server",
            "dhcpLeaseTime": "1 day",
            "reservedIpRanges": [],
            "fixedIpAssignments": {},
        }
        for vid, name in names.items()
    ]


def vlan(vlans: List[Dict[str, Any]], vid: int) -> Dict[str, Any]:
    return next(v for v in vlans if v["id"] == vid)


appliance_vlans = {
    NET_HQ: site_vlans(NET_HQ, 10),
    NET_EAST: site_vlans(NET_EAST, 20),
    NET_WEST: site_vlans(NET_WEST, 30),
}

# --- IPAM stories (address space, DHCP, reservations) ------------------------

# HQ guest: someone reserved .2-.200 "for kiosks" in 2019. The kiosks are long
# gone; the reservation isn't. DHCP has 54 addresses left to hand out, and the
# guest network is close to running dry at lunchtime.
vlan(appliance_vlans[NET_HQ], 30)["reservedIpRanges"] = [
    {"start": "10.10.30.2", "end": "10.10.30.200", "comment": "Reserved for lobby kiosks (2019)"}
]
# HQ corp: the lobby printer has a reservation for .50, but a conference-room TV
# that was given .50 statically is holding it. Two devices, one address.
MAC_PRINTER_LOBBY = "00:18:0a:aa:00:50"
MAC_CONF_TV = "00:18:0a:aa:00:51"
vlan(appliance_vlans[NET_HQ], 10)["fixedIpAssignments"] = {
    MAC_PRINTER_LOBBY: {"ip": "10.10.10.50", "name": "printer-lobby"},
}
# HQ lab: copied from Depot-East's config when the lab was set up, subnet and
# all. Invisible until the sites are joined by VPN or SD-WAN.
appliance_vlans[NET_HQ].append({
    "id": 50, "networkId": NET_HQ, "name": "Lab",
    "applianceIp": "10.20.10.1", "subnet": "10.20.10.0/24",
    "dhcpHandling": "Run a DHCP server", "dhcpLeaseTime": "1 day",
    "reservedIpRanges": [], "fixedIpAssignments": {},
})

# Depot-East corp: a reservation for a printer that was recycled two years ago.
MAC_OLD_PRINTER = "00:18:0a:bb:00:40"
vlan(appliance_vlans[NET_EAST], 10)["fixedIpAssignments"] = {
    MAC_OLD_PRINTER: {"ip": "10.20.10.40", "name": "old-printer-2nd-floor"},
}
# Depot-East management: a reservation typed as 10.20.2.15 in a 10.20.1.0/24
# VLAN. DHCP can never serve it, so the UPS takes a random lease instead and
# its monitoring points at an address nothing answers on.
MAC_UPS = "00:18:0a:bb:00:15"
vlan(appliance_vlans[NET_EAST], 1)["fixedIpAssignments"] = {
    MAC_UPS: {"ip": "10.20.2.15", "name": "ups-mgmt"},
}
# Depot-East voice: phones get DHCP from the central call server, not the MX.
vlan(appliance_vlans[NET_EAST], 20)["dhcpHandling"] = "Relay DHCP to another server"
vlan(appliance_vlans[NET_EAST], 20)["dhcpRelayServerIps"] = ["10.10.1.10"]


def mx_ports() -> List[Dict[str, Any]]:
    return [
        {"number": 3, "enabled": True, "type": "trunk", "dropUntaggedTraffic": False,
         "vlan": 1, "allowedVlans": "all", "accessPolicy": "open"},
        {"number": 4, "enabled": False, "type": "access", "dropUntaggedTraffic": False,
         "vlan": 1, "allowedVlans": "all", "accessPolicy": "open"},
    ]


appliance_ports = {NET_HQ: mx_ports(), NET_EAST: mx_ports(), NET_WEST: mx_ports()}


# ---------------------------------------------------------------- firewalls

def rule(policy, protocol, src, dst, dport="Any", comment="", syslog=False):
    return {
        "comment": comment,
        "policy": policy,
        "protocol": protocol,
        "srcPort": "Any",
        "srcCidr": src,
        "destPort": dport,
        "destCidr": dst,
        "syslogEnabled": syslog,
    }


DEFAULT_RULE = {
    "comment": "Default rule",
    "policy": "allow",
    "protocol": "Any",
    "srcPort": "Any",
    "srcCidr": "Any",
    "destPort": "Any",
    "destCidr": "Any",
    "syslogEnabled": False,
}

BASELINE_RULES = [
    rule("deny", "any", "VLAN(30).*", "10.0.0.0/8", comment="Guest cannot reach internal", syslog=True),
    rule("deny", "any", "VLAN(40).*", "VLAN(10).*", comment="Cameras cannot reach corp", syslog=True),
    rule("allow", "tcp", "VLAN(10).*", "VLAN(40).*", dport="443", comment="Corp to camera local streams"),
]

l3_rules = {
    NET_HQ: {"rules": [*BASELINE_RULES, DEFAULT_RULE]},
    NET_EAST: {
        "rules": [
            # Added for a monitoring vendor. Not in the standard, and Any->Any
            # SNMP is far broader than one collector needs.
            rule("allow", "udp", "Any", "Any", dport="161", comment="SNMP for monitoring vendor"),
            *BASELINE_RULES,
            DEFAULT_RULE,
        ]
    },
    NET_WEST: {
        "rules": [
            # Added during the cutover "temporarily". Placed above the guest
            # isolation rule, so first-match means guest isolation no longer
            # does anything.
            rule("allow", "any", "VLAN(30).*", "Any",
                 comment="TEMP vendor access during cutover - remove after"),
            *BASELINE_RULES,
            DEFAULT_RULE,
        ]
    },
}


# -------------------------------------------------------------------- SSIDs

def ssid(number, name, **overrides):
    base = {
        "number": number,
        "name": name,
        "enabled": True,
        "splashPage": "None",
        "ssidAdminAccessible": False,
        "authMode": "psk",
        "encryptionMode": "wpa",
        "wpaEncryptionMode": "WPA2 only",
        "ipAssignmentMode": "Bridge mode",
        "useVlanTagging": True,
        "defaultVlanId": 10,
        "minBitrate": 12,
        "bandSelection": "Dual band operation with Band Steering",
        "perClientBandwidthLimitUp": 0,
        "perClientBandwidthLimitDown": 0,
        "visible": True,
        "availableOnAllAps": True,
    }
    base.update(overrides)
    return base


def corp(number=0, **kw):
    return ssid(number, "CVL-Corp", authMode="8021x-radius", encryptionMode="wpa-eap",
                defaultVlanId=10, **kw)


def guest(number=1, **kw):
    params = {"defaultVlanId": 30}
    params.update(kw)
    return ssid(number, "CVL-Guest", **params)


def unconfigured(number):
    return ssid(number, f"Unconfigured SSID {number + 1}", enabled=False, authMode="open",
                encryptionMode=None, wpaEncryptionMode=None, ipAssignmentMode="NAT mode",
                useVlanTagging=False, defaultVlanId=None)


ssids = {
    NET_HQ: [corp(), guest(), unconfigured(2), unconfigured(3)],
    NET_EAST: [
        corp(bandSelection="Dual band operation"),
        guest(wpaEncryptionMode="WPA1 and WPA2"),
        unconfigured(2),
        unconfigured(3),
    ],
    NET_WEST: [
        corp(),
        guest(),
        # Left on after the installers finished. Open, and bridged straight
        # into the corp VLAN.
        ssid(2, "CVL-Install", authMode="open", encryptionMode=None, wpaEncryptionMode=None,
             defaultVlanId=10, visible=False),
        unconfigured(3),
    ],
}


# ----------------------------------------------------------------- topology

def end(serial, name, port_id):
    return {
        "node": {"derivedId": serial, "type": "device"},
        "device": {"serial": serial, "name": name},
        "discovered": {"lldp": {"portId": str(port_id)}, "cdp": None},
    }


def link(a, b):
    return {"ends": [a, b], "lastReportedAt": "2026-10-01T16:00:00Z"}


topology = {
    NET_HQ: {
        "links": [
            link(end("Q2XX-HQ00-SW01", "SW-HQ-CORE", 48), end("Q2XX-HQ00-MX01", "MX-HQ", 3)),
            link(end("Q2XX-HQ00-SW01", "SW-HQ-CORE", 47), end("Q2XX-HQ00-SW02", "SW-HQ-IDF1", 24)),
        ]
    },
    NET_EAST: {
        "links": [
            link(end("Q2XX-EA00-SW01", "SW-EAST-CORE", 24), end("Q2XX-EA00-MX01", "MX-EAST", 3)),
            link(end("Q2XX-EA00-SW01", "SW-EAST-CORE", 23), end("Q2XX-EA00-SW02", "SW-EAST-IDF1", 8)),
        ]
    },
    NET_WEST: {
        "links": [
            link(end("Q2XX-WE00-SW01", "SW-WEST-CORE", 24), end("Q2XX-WE00-MX01", "MX-WEST", 3)),
            link(end("Q2XX-WE00-SW01", "SW-WEST-CORE", 23), end("Q2XX-WE00-SW03", "SW-WEST-IDF1", 8)),
        ]
    },
}


# ------------------------------------------------------- 802.1X access policies
# GET /networks/{id}/switch/accessPolicies

def radius(host):
    return {"host": host, "port": 1812}


access_policies = {
    # HQ: the reference 802.1X design. Hybrid (802.1X, MAB fallback for phones
    # and printers), Multi-Domain so a phone and a PC can share a desk port,
    # two RADIUS servers, accounting on, failed auth lands in Guest.
    # One deliberate trade-off: if both RADIUS servers are unreachable, ports
    # fail OPEN into Corp ("critical auth"), so a RADIUS outage doesn't take
    # down every desk. That's a defensible choice and it should be a written
    # one; the audit reports it so it is.
    NET_HQ: [{
        "accessPolicyNumber": "1",
        "name": "Corp 802.1X",
        "accessPolicyType": "Hybrid authentication",
        "hostMode": "Multi-Domain",
        "radiusServers": [radius("10.10.1.10"), radius("10.10.1.11")],
        "radiusAccountingEnabled": True,
        "radiusCoaSupportEnabled": True,
        "guestVlanId": 30,
        "radius": {"criticalAuth": {"dataVlanId": 10, "voiceVlanId": 20, "suspendPortBounce": False},
                   "failedAuthVlanId": 30, "reAuthenticationInterval": 3600},
        "dot1x": {"controlDirection": "both"},
        "voiceVlanClients": True,
    }],
    # Depot-East: 802.1X was set up as Multi-Host to get a dispatch desk with a
    # small unmanaged switch under it working. Multi-Host authenticates the
    # first device and then opens the port to everything behind it.
    NET_EAST: [{
        "accessPolicyNumber": "1",
        "name": "Dispatch 802.1X",
        "accessPolicyType": "802.1x",
        "hostMode": "Multi-Host",
        "radiusServers": [radius("10.10.1.10")],
        "radiusAccountingEnabled": False,
        "radiusCoaSupportEnabled": False,
        "guestVlanId": None,
        "radius": {"criticalAuth": {"dataVlanId": None, "voiceVlanId": None, "suspendPortBounce": False},
                   "failedAuthVlanId": None, "reAuthenticationInterval": None},
        "dot1x": {"controlDirection": "both"},
        "voiceVlanClients": True,
    }],
    # Depot-West: 802.1X was never rolled out. Every port is open.
    NET_WEST: [],
}


# -------------------------------------------------------------------- clients
# GET /networks/{id}/clients?timespan=604800: everything seen in the last 7 days.

LAST_SEEN = 1790000000  # fixed epoch so fixtures are deterministic


def client(mac, ip, vlan_id, description, *, switch=None, port=None, user=None,
           os=None, manufacturer=None):
    """A client. switch/port set means wired, seen on that switch port.

    `user` is the 802.1X identity Dashboard records for a client that
    authenticated with a supplicant; it's empty for MAB and open ports.
    """
    return {"id": "k" + mac.replace(":", "")[-6:], "mac": mac, "ip": ip, "vlan": vlan_id,
            "description": description, "lastSeen": LAST_SEEN, "status": "Online",
            "recentDeviceSerial": switch, "switchport": str(port) if port else None,
            "user": user, "os": os, "manufacturer": manufacturer}


HQ_CORE, HQ_IDF = "Q2XX-HQ00-SW01", "Q2XX-HQ00-SW02"
EAST_CORE, EAST_IDF = "Q2XX-EA00-SW01", "Q2XX-EA00-SW02"
WEST_CORE, WEST_IDF = "Q2XX-WE00-SW01", "Q2XX-WE00-SW03"


def hq_laptop(i):
    """Laptops 0-6 are wired to desk ports; 7-11 are on Wi-Fi."""
    if i >= 7:
        return client(_mac("c1", i), f"10.10.10.{100 + i}", 10, f"laptop-{i:02d}",
                      os="macOS", manufacturer="Apple")
    switch, port_no = (HQ_CORE, i + 1) if i < 4 else (HQ_IDF, i - 3)
    if i == 6:
        # A Windows laptop authenticating by MAC address, not 802.1X: its
        # supplicant is off or broken, and its MAC was added to RADIUS so the
        # ticket could be closed. Anyone who copies that MAC gets Corp.
        return client(_mac("c1", i), f"10.10.10.{100 + i}", 10, f"laptop-{i:02d}",
                      switch=switch, port=port_no, os="Windows 11", manufacturer="Dell")
    return client(_mac("c1", i), f"10.10.10.{100 + i}", 10, f"laptop-{i:02d}",
                  switch=switch, port=port_no, user=f"user{i:02d}@cvl.example",
                  os="Windows 11", manufacturer="Dell")


def hq_guest(i):
    if i == 0:
        # Plugged into a desk port, failed 802.1X, landed in Guest. Works, sort
        # of; it's a ticket that hasn't been raised yet.
        return client(_mac("c3", i), f"10.10.30.{201 + i}", 30, "contractor-laptop",
                      switch=HQ_IDF, port=4, os="Windows 10", manufacturer="Lenovo")
    return client(_mac("c3", i), f"10.10.30.{201 + i}", 30, f"guest-{i:02d}")


def _mac(prefix: str, n: int) -> str:
    return f"00:18:0a:{prefix}:{n // 256:02x}:{n % 256:02x}"


clients = {
    NET_HQ: [
        *[hq_laptop(i) for i in range(12)],
        client(MAC_CONF_TV, "10.10.10.50", 10, "conference-room-tv"),
        # Desk phones: MAC authentication bypass is the expected path for these.
        *[client(_mac("c2", i), f"10.10.20.{100 + i}", 20, f"desk-phone-{i:02d}",
                 switch=HQ_CORE, port=i + 1, manufacturer="Cisco") for i in range(2)],
        # 50 guests in a pool of 54.
        *[hq_guest(i) for i in range(50)],
    ],
    NET_EAST: [
        *[client(_mac("e1", i), f"10.20.10.{100 + i}", 10, f"dispatch-{i:02d}",
                 switch=EAST_CORE if i < 3 else None, port=i + 1 if i < 3 else None,
                 user=f"dispatch{i:02d}@cvl.example" if i < 3 else None,
                 os="Windows 11", manufacturer="HP") for i in range(6)],
        client(MAC_UPS, "10.20.1.87", 1, "ups-mgmt"),
        *[client(_mac("e2", i), f"10.20.20.{100 + i}", 20, f"phone-{i:02d}") for i in range(4)],
    ],
    NET_WEST: [
        *[client(_mac("w1", i), f"10.30.10.{100 + i}", 10, f"dispatch-{i:02d}",
                 switch=WEST_CORE if i < 2 else None, port=i + 1 if i < 2 else None,
                 os="Windows 11", manufacturer="HP") for i in range(4)],
        # A consumer router plugged in at the wash bay, handing out its own
        # 192.168.1.0/24. The PC behind it works; nobody can find it. The port
        # is open, so nothing stopped it.
        client("00:18:0a:dd:00:01", "192.168.1.50", 10, "Wash bay PC",
               switch=WEST_IDF, port=6, os="Windows 10"),
    ],
}


def main() -> None:
    write("organizations", organizations)
    write("networks", networks)
    write("devices", devices)
    write("switch_ports", switch_ports)
    write("appliance_vlans", appliance_vlans)
    write("appliance_ports", appliance_ports)
    write("l3_firewall_rules", l3_rules)
    write("ssids", ssids)
    write("topology", topology)
    write("clients", clients)
    write("access_policies", access_policies)
    print(f"wrote fixtures to {OUT}")


if __name__ == "__main__":
    main()
