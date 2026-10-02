"""Compute a plan: the changes that would make live configuration match intent.

The output is a list of Changes, each with a Terraform-style action:

  + create   declared in intent, absent live (e.g. a new VLAN)
  ~ update   present in both, at least one declared attribute differs
  - delete   present live, absent from intent, in a section marked exclusive

Comparison is exact on declared attributes, with three normalisations where
Dashboard itself treats different spellings as the same value:

  * allowedVlans is compared as a set ("1-3" == "1,2,3", "1-4094" == "all"),
    and the change is annotated with exactly which VLANs it adds or removes;
  * tags are compared as a set (Dashboard doesn't preserve order);
  * "10" and 10 are the same VLAN (YAML keys and API values disagree on type).

Firewall rules are compared as an ordered list, because on an MX the order is
the behaviour. The diff is computed with difflib so a removed rule shows up
as one removal, not as every subsequent rule "changing".

Nothing here writes. A plan is a description, and this tool has no apply.
"""

from __future__ import annotations

import difflib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .checks.base import OrgContext
from .intent import Intent
from .scoring import VlanSet, format_vlans
from .state import L3_RULE_ATTRS, find_switch, read_network, switch_key

CREATE, UPDATE, DELETE = "create", "update", "delete"
SYMBOL = {CREATE: "+", UPDATE: "~", DELETE: "-"}

RULE_DEFAULTS = {"comment": "", "srcPort": "Any", "destPort": "Any", "syslogEnabled": False}


@dataclass
class AttrChange:
    attr: str
    old: Any
    new: Any
    note: str = ""


@dataclass
class RuleLine:
    op: str          # "+" or "-"
    position: int    # 1-based position in the list it belongs to
    rule: Dict[str, Any]


@dataclass
class Change:
    action: str
    network: str
    kind: str
    address: str
    label: str = ""
    attrs: List[AttrChange] = field(default_factory=list)
    rules: List[RuleLine] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Plan:
    org_name: str
    intent_source: str
    changes: List[Change] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    networks: List[str] = field(default_factory=list)

    def count(self, action: str) -> int:
        return sum(1 for c in self.changes if c.action == action)

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "organization": self.org_name,
            "intent": self.intent_source,
            "networks": self.networks,
            "summary": {a: self.count(a) for a in (CREATE, UPDATE, DELETE)},
            "changes": [c.to_dict() for c in self.changes],
            "errors": self.errors,
        }


def compute_plan(context: OrgContext, intent: Intent) -> Plan:
    plan = Plan(org_name=str(context.org.get("name", context.org_id)), intent_source=intent.source)
    by_name = {n.get("name"): n for n in context.all_networks}

    for net_name, declared in intent.networks.items():
        network = by_name.get(net_name)
        if network is None:
            plan.errors.append(
                f"Network '{net_name}' is in the intent but not in organization "
                f"'{plan.org_name}'. Networks can't be created by a plan; check the name."
            )
            continue
        plan.networks.append(net_name)
        live = read_network(context, network)
        exclusive = intent.exclusive.get(net_name, [])

        if "appliance_vlans" in declared:
            _plan_vlans(plan, net_name, network, context, declared["appliance_vlans"],
                        live.get("appliance_vlans"), "appliance_vlans" in exclusive)
        if "l3_firewall_rules" in declared:
            _plan_rules(plan, net_name, declared["l3_firewall_rules"], live.get("l3_firewall_rules"))
        if "switch_ports" in declared:
            _plan_ports(plan, net_name, network, context, declared["switch_ports"], live.get("switch_ports") or {})
        if "ssids" in declared:
            _plan_ssids(plan, net_name, network, context, declared["ssids"], live.get("ssids") or {})

    return plan


# ---------------------------------------------------------------- sections


def _plan_vlans(plan, net, network, context, declared, live, exclusive) -> None:
    if live is None and not context.has_product(network, "appliance"):
        plan.errors.append(f"{net}: intent declares appliance_vlans but the network has no MX.")
        return
    live = live or {}
    for vid in sorted(declared):
        address = f'network["{net}"].appliance_vlan[{vid}]'
        want = declared[vid]
        if vid not in live:
            plan.changes.append(Change(CREATE, net, "appliance_vlans", address, want.get("name", ""),
                                       [AttrChange(a, None, v) for a, v in want.items()]))
            continue
        diffs = _diff_attrs(want, live[vid])
        if diffs:
            plan.changes.append(Change(UPDATE, net, "appliance_vlans", address,
                                       str(live[vid].get("name", "")), diffs))
    if exclusive:
        for vid in sorted(set(live) - set(declared)):
            plan.changes.append(Change(
                DELETE, net, "appliance_vlans", f'network["{net}"].appliance_vlan[{vid}]',
                str(live[vid].get("name", "")),
                [AttrChange(a, v, None) for a, v in live[vid].items()],
            ))


def _plan_rules(plan, net, declared, live) -> None:
    if live is None:
        plan.errors.append(f"{net}: intent declares l3_firewall_rules but the network has no MX.")
        return
    want = [_canonical_rule(r) for r in declared]
    have = [_canonical_rule(r) for r in live]
    matcher = difflib.SequenceMatcher(a=[_rule_key(r) for r in have], b=[_rule_key(r) for r in want],
                                      autojunk=False)
    lines: List[RuleLine] = []
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag == "equal":
            continue
        for i in range(a0, a1):
            lines.append(RuleLine("-", i + 1, have[i]))
        for j in range(b0, b1):
            lines.append(RuleLine("+", j + 1, want[j]))
    if lines:
        removed = sum(1 for l in lines if l.op == "-")
        added = len(lines) - removed
        label = f"{len(have)} rules -> {len(want)} rules ({added} added, {removed} removed)"
        plan.changes.append(Change(UPDATE, net, "l3_firewall_rules",
                                   f'network["{net}"].l3_firewall_rules', label, rules=lines))


def _plan_ports(plan, net, network, context, declared, live) -> None:
    for key in sorted(declared):
        device = find_switch(context, network["id"], key)
        if device is None:
            plan.errors.append(f"{net}: switch '{key}' is in the intent but not in this network.")
            continue
        live_ports = live.get(switch_key(device), {})
        for port_id in sorted(declared[key], key=_port_order):
            address = f'network["{net}"].switch_port["{key}"]["{port_id}"]'
            if port_id not in live_ports:
                plan.errors.append(
                    f"{address}: port {port_id} doesn't exist on {key} "
                    f"({device.get('model', 'unknown model')}). Ports can't be created."
                )
                continue
            diffs = _diff_attrs(declared[key][port_id], live_ports[port_id])
            if diffs:
                plan.changes.append(Change(UPDATE, net, "switch_ports", address,
                                           str(live_ports[port_id].get("name") or ""), diffs))


def _plan_ssids(plan, net, network, context, declared, live) -> None:
    if not context.has_product(network, "wireless"):
        plan.errors.append(f"{net}: intent declares ssids but the network has no wireless.")
        return
    for number in sorted(declared):
        address = f'network["{net}"].ssid[{number}]'
        want = declared[number]
        if number not in live:
            # Every slot exists in Dashboard; an unconfigured one is "created"
            # in the sense that matters to a reviewer.
            plan.changes.append(Change(CREATE, net, "ssids", address, str(want.get("name", "")),
                                       [AttrChange(a, None, v) for a, v in want.items()]))
            continue
        diffs = _diff_attrs(want, live[number])
        if diffs:
            plan.changes.append(Change(UPDATE, net, "ssids", address, str(live[number].get("name", "")), diffs))


# ----------------------------------------------------------------- helpers


def _diff_attrs(want: Dict[str, Any], have: Dict[str, Any]) -> List[AttrChange]:
    out = []
    for attr, new in want.items():
        old = have.get(attr)
        if not values_equal(attr, old, new):
            out.append(AttrChange(attr, old, new, _note(attr, old, new)))
    return out


def values_equal(attr: str, a: Any, b: Any) -> bool:
    if attr == "allowedVlans":
        return _vlan_canonical(a) == _vlan_canonical(b)
    if attr == "tags":
        return sorted(a or []) == sorted(b or [])
    if isinstance(a, bool) or isinstance(b, bool):
        # In Python True == 1; in a config file they are different values.
        return type(a) is type(b) and a == b
    if _is_int_like(a) and _is_int_like(b):
        return int(a) == int(b)
    return a == b


def _note(attr: str, old: Any, new: Any) -> str:
    if attr != "allowedVlans":
        return ""
    o, n = VlanSet.parse(old), VlanSet.parse(new)
    if o.all or n.all:
        return ""
    added, removed = n.ids - o.ids, o.ids - n.ids
    parts = []
    if added:
        parts.append(f"+{format_vlans(added)}")
    if removed:
        parts.append(f"-{format_vlans(removed)}")
    return " ".join(parts)


def _vlan_canonical(value: Any) -> Tuple[bool, Tuple[int, ...]]:
    parsed = VlanSet.parse(value)
    return (parsed.all, tuple(sorted(parsed.ids)))


def _is_int_like(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, str) and value.strip().isdigit()


def _canonical_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    merged = {**RULE_DEFAULTS, **{k: v for k, v in rule.items() if v is not None}}
    return {a: merged.get(a) for a in L3_RULE_ATTRS}


def _rule_key(rule: Dict[str, Any]) -> Tuple:
    def norm(v):
        text = str(v).strip()
        return "any" if text.lower() == "any" else text
    return tuple(
        norm(rule[a]).lower() if a in ("policy", "protocol") else (rule[a] if a == "syslogEnabled" else norm(rule[a]))
        for a in L3_RULE_ATTRS
    )


def _port_order(port_id: str) -> Tuple[int, str]:
    return (int(port_id), "") if str(port_id).isdigit() else (10**6, str(port_id))


def describe_rule(rule: Dict[str, Any]) -> str:
    text = (
        f"{str(rule.get('policy', '')).upper()} {rule.get('protocol')} "
        f"{rule.get('srcCidr')}:{rule.get('srcPort')} -> {rule.get('destCidr')}:{rule.get('destPort')}"
    )
    if rule.get("comment"):
        text += f'  "{rule["comment"]}"'
    return text


def find_change(plan: Plan, address: str) -> Optional[Change]:
    return next((c for c in plan.changes if c.address == address), None)
