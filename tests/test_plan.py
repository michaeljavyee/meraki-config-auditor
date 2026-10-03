import json
from pathlib import Path

import pytest
import yaml

from src import export, plan
from src.diff import CREATE, DELETE, UPDATE, compute_plan, find_change, values_equal
from src.intent import IntentError, load_intent
from src.render_plan import render_markdown, render_text

ROOT = Path(__file__).resolve().parent.parent
DEMO_INTENT = ROOT / "intent" / "demo" / "cedar-valley.yaml"


def _write(tmp_path, data, name="intent.yaml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return path


# ------------------------------------------------------------ the core property

def test_export_then_plan_is_empty(demo_context, tmp_path):
    """Whatever export writes, plan must read back as 'no changes'."""
    snapshot = tmp_path / "snap.yaml"
    snapshot.write_text(export.dump_intent(export.export_org(demo_context), "test"))
    result = compute_plan(demo_context, load_intent(snapshot))
    assert result.changes == [] and result.errors == []


def test_plan_cli_exit_codes(tmp_path, capsys):
    snapshot = tmp_path / "snap.yaml"
    assert export.main(["--demo", "--output", str(snapshot)]) == 0
    assert plan.main(["--demo", "--intent", str(snapshot), "--format", "text"]) == 0
    assert plan.main(["--demo", "--format", "text"]) == 2           # demo intent has changes
    bad = _write(tmp_path, {"networks": {"Nowhere": {"ssids": {0: {"enabled": True}}}}})
    assert plan.main(["--demo", "--intent", str(bad), "--format", "text"]) == 1


# ------------------------------------------------------------- the demo story

@pytest.fixture
def demo_plan(demo_context):
    return compute_plan(demo_context, load_intent(DEMO_INTENT))


def test_demo_summary(demo_plan):
    assert (demo_plan.count(CREATE), demo_plan.count(UPDATE), demo_plan.count(DELETE)) == (1, 8, 0)
    assert demo_plan.errors == []


def test_demo_restores_camera_vlan_on_west_uplink(demo_plan):
    change = find_change(demo_plan, 'network["Depot-West"].switch_port["SW-WEST-IDF1"]["8"]')
    assert [(a.attr, a.note) for a in change.attrs] == [("allowedVlans", "+40")]


def test_demo_removes_only_the_temp_rule(demo_plan):
    change = find_change(demo_plan, 'network["Depot-West"].l3_firewall_rules')
    assert [(r.op, r.position) for r in change.rules] == [("-", 1)]
    assert "TEMP" in change.rules[0].rule["comment"]


def test_demo_creates_planned_vlan(demo_plan):
    change = find_change(demo_plan, 'network["Depot-West"].appliance_vlan[50]')
    assert change.action == CREATE


def test_unmanaged_attributes_are_ignored(demo_plan):
    # The intent never mentions PoE or STP; no change may mention them.
    attrs = {a.attr for c in demo_plan.changes for a in c.attrs}
    assert not attrs & {"poeEnabled", "rstpEnabled", "stpGuard"}


# --------------------------------------------------------------- unit cases

def test_exclusive_vlans_plan_deletion(demo_context, tmp_path):
    path = _write(tmp_path, {"networks": {"HQ": {
        "exclusive": ["appliance_vlans"],
        "appliance_vlans": {1: {"name": "Management"}},
    }}})
    result = compute_plan(demo_context, load_intent(path))
    deleted = sorted(c.address for c in result.changes if c.action == DELETE)
    assert deleted == [f'network["HQ"].appliance_vlan[{v}]' for v in (10, 20, 30, 40, 50)]


def test_inserted_rule_is_one_addition_not_a_cascade(demo_context, tmp_path):
    rules = yaml.safe_load(DEMO_INTENT.read_text())["definitions"]["firewall"]
    new = {"comment": "Block guest SMTP", "policy": "deny", "protocol": "tcp",
           "srcCidr": "VLAN(30).*", "destCidr": "Any", "destPort": "25"}
    path = _write(tmp_path, {"networks": {"HQ": {"l3_firewall_rules": [new] + rules}}})
    change = compute_plan(demo_context, load_intent(path)).changes[0]
    assert [(r.op, r.position) for r in change.rules] == [("+", 1)]


def test_missing_switch_and_port_are_errors(demo_context, tmp_path):
    path = _write(tmp_path, {"networks": {"HQ": {"switch_ports": {
        "SW-NOPE": {"1": {"vlan": 10}},
        "SW-HQ-IDF1": {"99": {"vlan": 10}},
    }}}})
    errors = compute_plan(demo_context, load_intent(path)).errors
    assert any("SW-NOPE" in e for e in errors)
    assert any('["99"]' in e for e in errors)


@pytest.mark.parametrize("attr, a, b, equal", [
    ("allowedVlans", "1-3,10", "1,2,3,10", True),
    ("allowedVlans", "1-4094", "all", True),
    ("allowedVlans", "1,10", "1,10,40", False),
    ("tags", ["b", "a"], ["a", "b"], True),
    ("vlan", "10", 10, True),
    ("enabled", True, 1, False),
    ("name", "Uplink", "uplink", False),
])
def test_values_equal(attr, a, b, equal):
    assert values_equal(attr, a, b) is equal


def test_intent_rejects_unknown_attribute(tmp_path):
    path = _write(tmp_path, {"networks": {"HQ": {"ssids": {0: {"colour": "blue"}}}}})
    with pytest.raises(IntentError, match="colour"):
        load_intent(path)


def test_intent_rejects_exclusive_ports(tmp_path):
    path = _write(tmp_path, {"networks": {"HQ": {"exclusive": ["switch_ports"]}}})
    with pytest.raises(IntentError, match="can't be exclusive"):
        load_intent(path)


def test_intent_directory_rejects_duplicate_network(tmp_path):
    for name in ("a.yaml", "b.yaml"):
        _write(tmp_path, {"networks": {"HQ": {"ssids": {0: {"enabled": True}}}}}, name)
    with pytest.raises(IntentError, match="more than one"):
        load_intent(tmp_path)


def test_markdown_and_json_renderers(demo_plan):
    md = render_markdown(demo_plan)
    assert md.startswith("### Meraki plan") and "```diff" in md
    assert "! network[" in md                       # updates get a visible marker
    data = json.loads(plan.render_json(demo_plan))
    assert data["summary"] == {"create": 1, "update": 8, "delete": 0}
    assert "Plan: 1 to add, 8 to change, 0 to destroy." in render_text(demo_plan)
