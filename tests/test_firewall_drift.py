import copy

from src.checks import firewall_drift
from src.scoring import HIGH, LOW, MEDIUM

NET = {"id": "N1", "name": "Site", "productTypes": ["appliance"], "tags": []}
DEFAULT = {"comment": "Default rule", "policy": "allow", "protocol": "Any", "srcPort": "Any",
           "srcCidr": "Any", "destPort": "Any", "destCidr": "Any"}


def _ctx(stub_context, baseline, rules):
    return stub_context({
        "/organizations/1/networks": [NET],
        "/networks/N1/appliance/firewall/l3FirewallRules": {"rules": [*rules, DEFAULT]},
    })


def _baseline_rules(baseline):
    return copy.deepcopy(baseline.firewall_rules)


def _rule(policy, protocol, src, dst, dport="Any", comment=""):
    return {"comment": comment, "policy": policy, "protocol": protocol, "srcPort": "Any",
            "srcCidr": src, "destPort": dport, "destCidr": dst}


# ---------------------------------------------------------------- demo story

def test_demo_hq_is_compliant(demo_context):
    assert not [f for f in firewall_drift.run(demo_context) if f.network == "HQ"]


def test_demo_west_temp_rule_shadows_guest_isolation(demo_context):
    west = [f for f in firewall_drift.run(demo_context) if f.network == "Depot-West"]
    assert len(west) == 1
    assert west[0].severity == HIGH
    assert "Guest cannot reach internal" in west[0].finding


def test_demo_east_broad_snmp_is_medium(demo_context):
    east = [f for f in firewall_drift.run(demo_context) if f.network == "Depot-East"]
    assert [(f.severity, f.metadata.get("rule_index")) for f in east] == [(MEDIUM, 1)]


# -------------------------------------------------------------- unit cases

def test_comment_differences_are_ignored(stub_context, baseline):
    rules = _baseline_rules(baseline)
    for r in rules:
        r["comment"] = "reworded"
    assert firewall_drift.run(_ctx(stub_context, baseline, rules)) == []


def test_case_and_whitespace_are_ignored(stub_context, baseline):
    rules = _baseline_rules(baseline)
    rules[0]["protocol"] = "ANY"
    rules[0]["srcPort"] = " any "
    assert firewall_drift.run(_ctx(stub_context, baseline, rules)) == []


def test_missing_deny_is_high(stub_context, baseline):
    rules = _baseline_rules(baseline)[1:]
    findings = firewall_drift.run(_ctx(stub_context, baseline, rules))
    assert [f.severity for f in findings] == [HIGH]
    assert "missing" in findings[0].finding


def test_missing_allow_is_low(stub_context, baseline):
    rules = _baseline_rules(baseline)[:2]
    assert [f.severity for f in firewall_drift.run(_ctx(stub_context, baseline, rules))] == [LOW]


def test_reorder_is_medium(stub_context, baseline):
    rules = _baseline_rules(baseline)
    rules[0], rules[1] = rules[1], rules[0]
    assert [f.severity for f in firewall_drift.run(_ctx(stub_context, baseline, rules))] == [MEDIUM]


def test_cidr_supernet_shadows(stub_context, baseline):
    # allow 10.0.0.0/8 covers the baseline deny's 10.0.0.0/8 destination only
    # if the source also covers VLAN(30).* - "Any" does.
    rules = [_rule("allow", "any", "Any", "10.0.0.0/8")] + _baseline_rules(baseline)
    findings = firewall_drift.run(_ctx(stub_context, baseline, rules))
    assert len(findings) == 1 and findings[0].severity == HIGH
    assert "overrides" in findings[0].finding


def test_narrow_extra_allow_does_not_shadow(stub_context, baseline):
    rules = [_rule("allow", "tcp", "VLAN(30).*", "10.0.5.10/32", dport="443")] + _baseline_rules(baseline)
    findings = firewall_drift.run(_ctx(stub_context, baseline, rules))
    assert [f.severity for f in findings] == [LOW]


def test_network_without_mx_is_skipped(stub_context, baseline):
    ctx = stub_context({"/organizations/1/networks": [{**NET, "productTypes": ["switch"]}]})
    assert firewall_drift.run(ctx) == []


def test_covers_value():
    assert firewall_drift._covers_value("any", "10.1.0.0/16")
    assert firewall_drift._covers_value("10.0.0.0/8", "10.1.0.0/16")
    assert not firewall_drift._covers_value("10.1.0.0/16", "10.0.0.0/8")
    assert not firewall_drift._covers_value("vlan(30).*", "vlan(40).*")
    assert firewall_drift._covers_value("10.0.0.0/8,192.168.0.0/16", "10.2.0.0/16")
