import copy

from src.checks import nac
from src.scoring import HIGH, LOW, MEDIUM

NET = {"id": "N1", "name": "Site", "productTypes": ["switch"], "tags": []}
SW = {"serial": "S1", "name": "SW1", "networkId": "N1", "productType": "switch"}

GOOD_POLICY = {
    "accessPolicyNumber": "1", "name": "Corp", "accessPolicyType": "Hybrid authentication",
    "hostMode": "Multi-Domain", "radiusServers": [{"host": "a"}, {"host": "b"}],
    "radiusAccountingEnabled": True, "guestVlanId": 30,
    "radius": {"criticalAuth": {"dataVlanId": None}, "failedAuthVlanId": 30},
}


def _port(pid, policy=None, tags=None, vlan=10, ptype="access"):
    p = {"portId": str(pid), "name": f"p{pid}", "type": ptype, "enabled": True, "vlan": vlan,
         "tags": tags or [], "accessPolicyType": "Open"}
    if policy:
        p.update(accessPolicyType="Custom access policy", accessPolicyNumber=policy)
    return p


def _client(pid, vlan=10, user=None, os=None, mac=None):
    return {"mac": mac or f"m{pid}", "ip": f"10.0.{vlan}.{pid}", "vlan": vlan, "description": f"c{pid}",
            "recentDeviceSerial": "S1", "switchport": str(pid), "user": user, "os": os}


def _ctx(stub_context, policies, ports, clients=()):
    return stub_context({
        "/organizations/1/networks": [NET],
        "/organizations/1/devices": [SW],
        "/devices/S1/switch/ports": ports,
        "/networks/N1/switch/accessPolicies": policies,
        "/networks/N1/clients": list(clients),
    })


def _policy(**overrides):
    p = copy.deepcopy(GOOD_POLICY)
    for k, v in overrides.items():
        if k == "radius":
            p["radius"].update(v)
        else:
            p[k] = v
    return p


# ---------------------------------------------------------------- demo story

def test_demo_findings(demo_context):
    found = sorted((f.network, f.severity, f.finding.split(" ")[0]) for f in nac.run(demo_context))
    assert [(n, s) for n, s, _ in found] == sorted([
        ("Depot-East", HIGH), ("Depot-East", MEDIUM), ("Depot-East", LOW), ("Depot-East", MEDIUM),
        ("Depot-West", HIGH),
        ("HQ", MEDIUM), ("HQ", HIGH), ("HQ", MEDIUM),
    ])


def test_demo_west_is_one_site_level_finding(demo_context):
    west = [f for f in nac.run(demo_context) if f.network == "Depot-West"]
    assert len(west) == 1 and "No access port" in west[0].finding


def test_demo_posture_counts(demo_context):
    nac.run(demo_context)
    idf = next(r for r in demo_context.nac_posture if r["switch"] == "SW-HQ-IDF1")
    assert (idf["dot1x"], idf["mab"], idf["failed"]) == (2, 1, 1)


# -------------------------------------------------------------- unit cases

def test_clean_design_has_no_findings(stub_context):
    ctx = _ctx(stub_context, [_policy()], [_port(1, policy="1"), _port(2, tags=["nac-exempt"])],
               [_client(1, user="alice", os="Windows 11")])
    assert nac.run(ctx) == []


def test_multi_host_is_high(stub_context):
    ctx = _ctx(stub_context, [_policy(hostMode="Multi-Host")], [_port(1, policy="1")])
    assert [f.severity for f in nac.run(ctx)] == [HIGH]


def test_guest_vlan_must_be_a_guest_vlan(stub_context):
    ctx = _ctx(stub_context, [_policy(guestVlanId=10)], [_port(1, policy="1")])
    findings = nac.run(ctx)
    assert [f.severity for f in findings] == [HIGH] and "VLAN 10 (corp)" in findings[0].finding


def test_fail_open_is_medium(stub_context):
    ctx = _ctx(stub_context, [_policy(radius={"criticalAuth": {"dataVlanId": 10}})], [_port(1, policy="1")])
    assert [f.severity for f in nac.run(ctx)] == [MEDIUM]


def test_mab_phone_is_counted_not_flagged(stub_context):
    ctx = _ctx(stub_context, [_policy()], [_port(1, policy="1")], [_client(1, vlan=20, os=None)])
    assert nac.run(ctx) == []
    assert ctx.nac_posture[0]["mab"] == 1


def test_mab_laptop_is_high(stub_context):
    ctx = _ctx(stub_context, [_policy()], [_port(1, policy="1")], [_client(1, os="macOS 14")])
    assert [f.severity for f in nac.run(ctx)] == [HIGH]


def test_open_ports_on_partly_enforcing_switch_are_medium(stub_context):
    ctx = _ctx(stub_context, [_policy()], [_port(1, policy="1"), _port(2), _port(3)])
    findings = nac.run(ctx)
    assert [f.severity for f in findings] == [MEDIUM] and "(2, 3)" in findings[0].finding


def test_trunks_and_disabled_ports_are_not_coverage_gaps(stub_context):
    disabled = _port(3)
    disabled["enabled"] = False
    ctx = _ctx(stub_context, [_policy()], [_port(1, policy="1"), _port(2, ptype="trunk"), disabled])
    assert nac.run(ctx) == []


def test_missing_policy_reference_is_high(stub_context):
    ctx = _ctx(stub_context, [_policy()], [_port(1, policy="7")])
    assert [f.severity for f in nac.run(ctx)] == [HIGH]
