from src.checks import ipam
from src.scoring import HIGH, LOW, MEDIUM

NET = {"id": "N1", "name": "Site", "productTypes": ["appliance"], "tags": []}


def _vlan(vid=10, subnet="10.0.10.0/24", **kw):
    v = {"id": vid, "name": f"V{vid}", "subnet": subnet, "applianceIp": "10.0.10.1",
         "dhcpHandling": "Run a DHCP server", "reservedIpRanges": [], "fixedIpAssignments": {}}
    v.update(kw)
    return v


def _client(mac, ip, vlan=10, desc=None):
    return {"mac": mac, "ip": ip, "vlan": vlan, "description": desc or mac}


def _ctx(stub_context, vlans, clients=(), networks=None, extra=None):
    routes = {
        "/organizations/1/networks": networks or [NET],
        "/networks/N1/appliance/vlans": vlans,
        "/networks/N1/clients": list(clients),
    }
    routes.update(extra or {})
    return stub_context(routes)


def _sev(findings):
    return sorted((f.severity, f.finding.split(" ")[0]) for f in findings)


# ---------------------------------------------------------------- demo story

def test_demo_findings(demo_context):
    found = {(f.network, f.severity, f.metadata.get("ip") or f.target) for f in ipam.run(demo_context)}
    assert found == {
        ("HQ", HIGH, "10.10.10.50"),                       # reservation held by the conference TV
        ("HQ", HIGH, "HQ / VLAN 30 (Guest)"),              # guest pool 93%
        ("Depot-East", HIGH, "10.20.2.15"),                # UPS reservation outside its subnet
        ("Depot-East", LOW, "10.20.10.40"),                # printer that no longer exists
        ("Depot-East", MEDIUM, "Depot-East VLAN 10 & HQ VLAN 50"),  # copied lab subnet
        ("Depot-West", MEDIUM, "192.168.1.50"),            # consumer router at the wash bay
    }


def test_demo_pool_math(demo_context):
    ipam.run(demo_context)
    guest = next(r for r in demo_context.address_space if r["network"] == "HQ" and r["vlan"] == 30)
    # 254 hosts - appliance IP - 199 reserved (.2-.200) = 54; 50 in use.
    assert (guest["pool"], guest["in_use"]) == (54, 50)


def test_relay_vlan_is_a_limitation_not_a_finding(demo_context):
    findings = ipam.run(demo_context)
    assert not any("VLAN 20 (Voice)" in f.target for f in findings)
    assert any("Relay DHCP" in s for s in demo_context.scope_limitations)


# -------------------------------------------------------------- unit cases

def test_pool_thresholds(stub_context):
    # /27: 30 hosts, minus appliance IP = 29 in the pool.
    vlan = _vlan(subnet="10.0.10.0/27", applianceIp="10.0.10.1")
    medium = [_client(f"m{i}", f"10.0.10.{2 + i}") for i in range(24)]   # 24/29 = 83%
    high = [_client(f"m{i}", f"10.0.10.{2 + i}") for i in range(27)]     # 27/29 = 93%
    assert [f.severity for f in ipam.run(_ctx(stub_context, [vlan], medium))] == [MEDIUM]
    assert [f.severity for f in ipam.run(_ctx(stub_context, [vlan], high))] == [HIGH]


def test_same_ip_seen_twice_counts_once(stub_context):
    vlan = _vlan(subnet="10.0.10.0/29", applianceIp="10.0.10.1")       # 6 hosts, pool 5
    clients = [_client("a", "10.0.10.2"), _client("b", "10.0.10.2")]   # lease churn, one address
    assert ipam.run(_ctx(stub_context, [vlan], clients)) == []


def test_overlap_within_network_is_high(stub_context):
    vlans = [_vlan(10, "10.0.10.0/24"), _vlan(11, "10.0.10.128/25", applianceIp="10.0.10.129")]
    assert [f.severity for f in ipam.run(_ctx(stub_context, vlans))] == [HIGH]


def test_reservation_for_present_device_is_clean(stub_context):
    vlan = _vlan(fixedIpAssignments={"aa": {"ip": "10.0.10.20", "name": "printer"}})
    assert ipam.run(_ctx(stub_context, [vlan], [_client("aa", "10.0.10.20")])) == []


def test_mac_comparison_is_case_insensitive(stub_context):
    vlan = _vlan(fixedIpAssignments={"AA:BB": {"ip": "10.0.10.20", "name": "printer"}})
    assert ipam.run(_ctx(stub_context, [vlan], [_client("aa:bb", "10.0.10.20")])) == []


def test_link_local_clients_are_ignored(stub_context):
    assert ipam.run(_ctx(stub_context, [_vlan()], [_client("x", "169.254.3.4")])) == []


def test_network_without_mx_is_skipped(stub_context):
    ctx = _ctx(stub_context, [], networks=[{**NET, "productTypes": ["switch"]}])
    assert ipam.run(ctx) == []
