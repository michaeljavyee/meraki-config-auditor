from src.checks import vlan_trunks
from src.scoring import CRITICAL, HIGH, MEDIUM

NET = {"id": "N1", "name": "Site", "productTypes": ["switch"], "tags": []}
SW = {"serial": "S1", "name": "SW1", "networkId": "N1", "productType": "switch", "model": "MS130-8P"}


def _routes(ports, topology=None):
    routes = {
        "/organizations/1/networks": [NET],
        "/organizations/1/devices": [SW],
        "/devices/S1/switch/ports": ports,
    }
    if topology is not None:
        routes["/networks/N1/topology/linkLayer"] = topology
    return routes


def _access(pid, vlan, voice=None, enabled=True):
    return {"portId": str(pid), "type": "access", "vlan": vlan, "voiceVlan": voice, "enabled": enabled}


def _uplink(pid, allowed, native=1, name="Uplink", tags=None):
    return {"portId": str(pid), "type": "trunk", "vlan": native, "allowedVlans": allowed,
            "name": name, "tags": tags or [], "enabled": True}


# ---------------------------------------------------------------- demo story

def test_demo_flags_west_camera_vlan_as_critical(demo_context):
    findings = vlan_trunks.run(demo_context)
    critical = [f for f in findings if f.severity == CRITICAL]
    assert len(critical) == 1
    assert critical[0].device == "SW-WEST-IDF1"
    assert critical[0].metadata["vlans"] == [40]
    assert critical[0].metadata["affected_ports"] == ["1", "2", "3", "4", "5"]


def test_demo_flags_east_native_mismatch_once(demo_context):
    findings = vlan_trunks.run(demo_context)
    east = [f for f in findings if f.network == "Depot-East"]
    # One HIGH link finding; the per-port "native differs from baseline"
    # MEDIUM is suppressed because the link finding already covers it.
    assert [f.severity for f in east] == [HIGH]


def test_demo_hq_latent_gap_is_medium(demo_context):
    hq = [f for f in vlan_trunks.run(demo_context) if f.network == "HQ"]
    assert [(f.severity, f.metadata.get("missing_vlans")) for f in hq] == [(MEDIUM, [40])]


# -------------------------------------------------------------- unit cases

def test_voice_vlan_counts_as_in_use(stub_context):
    ctx = stub_context(_routes([_access(1, 10, voice=20), _uplink(8, "1,10,30,40")]))
    critical = [f for f in vlan_trunks.run(ctx) if f.severity == CRITICAL]
    assert critical and critical[0].metadata["vlans"] == [20]


def test_disabled_ports_are_not_cut_off(stub_context):
    ctx = stub_context(_routes([_access(1, 99, enabled=False), _uplink(8, "1,10,20,30,40")]))
    assert vlan_trunks.run(ctx) == []


def test_allowed_all_never_missing(stub_context):
    ctx = stub_context(_routes([_access(1, 777), _uplink(8, "all")]))
    assert vlan_trunks.run(ctx) == []


def test_uplink_identified_by_tag_when_name_is_generic(stub_context):
    ctx = stub_context(_routes([_access(1, 40), _uplink(8, "1,10,20,30", name="Port 8", tags=["uplink"])]))
    assert any(f.severity == CRITICAL for f in vlan_trunks.run(ctx))


def test_unidentifiable_uplink_is_a_scope_limitation(stub_context):
    ctx = stub_context(_routes([_access(1, 40), _uplink(8, "1", name="Port 8")]))
    assert vlan_trunks.run(ctx) == []
    assert any("could not be identified" in s for s in ctx.scope_limitations)


def test_cut_off_vlan_not_double_reported_as_latent(stub_context):
    ctx = stub_context(_routes([_access(1, 40), _uplink(8, "1,10,20,30")]))
    findings = vlan_trunks.run(ctx)
    assert [f.severity for f in findings] == [CRITICAL]


def test_port_id_normalisation():
    assert vlan_trunks._normalise_port_id("Port 8") == "8"
    assert vlan_trunks._normalise_port_id("GigabitEthernet1/0/24") == "24"
    assert vlan_trunks._normalise_port_id(None) == ""
