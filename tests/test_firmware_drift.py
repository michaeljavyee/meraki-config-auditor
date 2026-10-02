from src.checks import firmware_drift
from src.scoring import LOW, MEDIUM

NET = {"id": "N1", "name": "Site", "productTypes": ["switch"], "tags": []}


def _sw(name, fw):
    return {"name": name, "serial": f"S-{name}", "networkId": "N1", "productType": "switch",
            "model": "MS130-8P", "firmware": fw}


def _ctx(stub_context, devices):
    return stub_context({"/organizations/1/networks": [NET], "/organizations/1/devices": devices})


def test_parse_version():
    assert firmware_drift.parse_version("switch-17-1-4") == (17, 1, 4)
    assert firmware_drift.parse_version("wired-18-2-11") > firmware_drift.parse_version("wired-18-2-9")
    assert firmware_drift.parse_version("Not running configured version") is None
    assert firmware_drift.parse_version(None) is None


def test_demo_findings(demo_context):
    found = {(f.device, f.severity) for f in firmware_drift.run(demo_context)}
    assert found == {("SW-WEST-IDF1", MEDIUM), ("MX-WEST", LOW), ("AP-EAST-01", LOW)}


def test_mixed_within_site_is_medium(stub_context):
    ctx = _ctx(stub_context, [_sw("A", "switch-17-1-4"), _sw("B", "switch-17-1-2")])
    assert [(f.device, f.severity) for f in firmware_drift.run(ctx)] == [("B", MEDIUM)]


def test_consistently_behind_is_low(stub_context):
    ctx = _ctx(stub_context, [_sw("A", "switch-17-1-2"), _sw("B", "switch-17-1-2")])
    assert {f.severity for f in firmware_drift.run(ctx)} == {LOW}


def test_unparseable_firmware_is_low(stub_context):
    ctx = _ctx(stub_context, [_sw("A", "unknown-build")])
    findings = firmware_drift.run(ctx)
    assert findings[0].severity == LOW and "could not be compared" in findings[0].finding


def test_not_running_configured_version_is_explained(stub_context):
    # Dashboard's literal value for a device that never applied its firmware,
    # observed on a live DevNet sandbox org.
    ctx = _ctx(stub_context, [_sw("A", "Not running configured version")])
    findings = firmware_drift.run(ctx)
    assert findings[0].severity == LOW
    assert "not running its network's configured firmware" in findings[0].finding
