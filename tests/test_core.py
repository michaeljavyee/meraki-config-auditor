from pathlib import Path

import pytest

from src.baseline import BaselineError, load_baseline
from src.scoring import CRITICAL, Finding, VlanSet, format_vlans

EXAMPLE = Path(__file__).resolve().parent.parent / "baselines" / "example.yaml"


@pytest.mark.parametrize(
    "text, contains, absent",
    [
        ("all", [1, 40, 4094], []),
        ("1,10,20,30", [1, 30], [40]),
        ("1-3,10", [2, 10], [4]),
        ("1-4094", [4000], []),
        ("", [], [1]),
        (None, [], [1]),
    ],
)
def test_vlan_set_parse(text, contains, absent):
    vlans = VlanSet.parse(text)
    for vid in contains:
        assert vid in vlans
    for vid in absent:
        assert vid not in vlans


def test_vlan_set_missing_handles_all():
    assert VlanSet.parse("all").missing({1, 40}) == set()
    assert VlanSet.parse("1,10").missing({1, 10, 40}) == {40}


def test_format_vlans_compacts_ranges():
    assert format_vlans({1, 2, 3, 10, 20, 21}) == "1-3,10,20-21"


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        Finding(category="firmware", target="x", severity="urgent", finding="", evidence="",
                risk="", remediation="")


def test_finding_rejects_unknown_category():
    with pytest.raises(ValueError):
        Finding(category="dns", target="x", severity=CRITICAL, finding="", evidence="",
                risk="", remediation="")


def test_example_baseline_loads():
    baseline = load_baseline(EXAMPLE)
    assert 40 in baseline.trunks.required_vlans
    assert baseline.vlan_label(40) == "VLAN 40 (cameras)"
    assert baseline.firmware["switch"] == "switch-17-1-4"
    assert len(baseline.firewall_rules) == 3


def test_baseline_rejects_bad_vlan(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("trunks:\n  required_vlans: [1, 5000]\n")
    with pytest.raises(BaselineError, match="outside 1-4094"):
        load_baseline(bad)


def test_baseline_rejects_incomplete_rule(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("firewall:\n  l3_rules:\n    - policy: deny\n      protocol: any\n")
    with pytest.raises(BaselineError, match="srcCidr"):
        load_baseline(bad)


def test_missing_baseline_points_at_example(tmp_path):
    with pytest.raises(BaselineError, match="example.yaml"):
        load_baseline(tmp_path / "nope.yaml")
