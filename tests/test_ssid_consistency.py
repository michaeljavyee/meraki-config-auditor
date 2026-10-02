from src.checks import ssid_consistency
from src.scoring import HIGH, LOW, MEDIUM

NET = {"id": "N1", "name": "Site", "productTypes": ["wireless"], "tags": []}


def _corp(**kw):
    ssid = {"number": 0, "name": "CVL-Corp", "enabled": True, "authMode": "8021x-radius",
            "encryptionMode": "wpa-eap", "wpaEncryptionMode": "WPA2 only",
            "ipAssignmentMode": "Bridge mode", "useVlanTagging": True, "defaultVlanId": 10,
            "bandSelection": "Dual band operation with Band Steering", "visible": True}
    ssid.update(kw)
    return ssid


def _guest(**kw):
    return _corp(number=1, name="CVL-Guest", authMode="psk", encryptionMode="wpa",
                 defaultVlanId=30, **kw)


def _ctx(stub_context, ssids):
    return stub_context({"/organizations/1/networks": [NET], "/networks/N1/wireless/ssids": ssids})


def test_demo_findings(demo_context):
    found = {(f.network, f.target.split("'")[1], f.severity) for f in ssid_consistency.run(demo_context)}
    assert found == {
        ("Depot-East", "CVL-Corp", LOW),
        ("Depot-East", "CVL-Guest", MEDIUM),
        ("Depot-West", "CVL-Install", HIGH),
    }


def test_compliant_site(stub_context):
    assert ssid_consistency.run(_ctx(stub_context, [_corp(), _guest()])) == []


def test_worst_field_sets_severity(stub_context):
    findings = ssid_consistency.run(_ctx(stub_context, [_corp(defaultVlanId=1, bandSelection="x"), _guest()]))
    assert len(findings) == 1 and findings[0].severity == HIGH
    assert set(findings[0].metadata["fields"]) == {"defaultVlanId", "bandSelection"}


def test_disabled_standard_ssid_counts_as_missing(stub_context):
    findings = ssid_consistency.run(_ctx(stub_context, [_corp(enabled=False), _guest()]))
    assert [(f.severity, "not enabled" in f.finding) for f in findings] == [(MEDIUM, True)]


def test_unknown_psk_ssid_is_medium(stub_context):
    extra = _corp(number=2, name="Lab", authMode="psk")
    findings = ssid_consistency.run(_ctx(stub_context, [_corp(), _guest(), extra]))
    assert [f.severity for f in findings] == [MEDIUM]


def test_disabled_unknown_ssid_ignored(stub_context):
    extra = _corp(number=2, name="Unconfigured SSID 3", enabled=False, authMode="open")
    assert ssid_consistency.run(_ctx(stub_context, [_corp(), _guest(), extra])) == []


def test_string_comparison_is_case_insensitive(stub_context):
    assert ssid_consistency.run(_ctx(stub_context, [_corp(wpaEncryptionMode="wpa2 ONLY"), _guest()])) == []
