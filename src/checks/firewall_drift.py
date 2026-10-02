"""Check 2 - MX L3 firewall rule drift from the baseline.

Firewall policy rarely breaks in one dramatic change. It accretes: an allow
rule for a vendor, a "temporary" rule during a migration, a rule copied from
another site that didn't quite fit. Each one is reasonable on the day. Nobody
removes them, because nobody is sure what depends on them.

This check compares each MX's outbound L3 rules with the baseline policy and
reports four kinds of drift, most severe first:

  * An extra rule that SHADOWS a baseline rule. Meraki evaluates rules top to
    bottom and stops at the first match, so an allow placed above a baseline
    deny that it fully covers makes the deny dead code. The policy looks
    correct in Dashboard and does nothing.                              HIGH
  * A baseline deny rule that is missing entirely.                      HIGH
  * An extra allow rule not in the standard. Severity scales with breadth:
    any destination on any port is HIGH, any-to-any on one port MEDIUM, a
    narrowly-scoped allow LOW.
  * Baseline rules present but in a different order.                  MEDIUM

Rules are compared on (policy, protocol, source, source port, destination,
destination port). Comments are ignored - they document intent but don't
change behaviour, and they are the field most likely to differ harmlessly.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from ..scoring import CAT_FIREWALL, HIGH, LOW, MEDIUM, Finding
from .base import OrgContext

CHECK_NAME = "firewall_drift"

RuleKey = Tuple[str, str, str, str, str, str]
FIELDS = ("policy", "protocol", "srcCidr", "srcPort", "destCidr", "destPort")


def run(context: OrgContext) -> List[Finding]:
    findings: List[Finding] = []
    baseline_rules = context.baseline.firewall_rules
    if not baseline_rules:
        context.note_limitation(
            "The baseline defines no firewall policy, so firewall drift was not assessed."
        )
        return findings

    expected = [_key(r) for r in baseline_rules]
    expected_by_key = {_key(r): r for r in baseline_rules}

    for network in context.networks:
        if not context.has_product(network, "appliance"):
            continue
        net_name = network.get("name", network["id"])
        live_raw = context.l3_firewall_rules(network["id"])
        if live_raw is None:
            context.note_limitation(
                f"L3 firewall rules could not be read for {net_name}."
            )
            continue

        live_rules = _strip_default(live_raw)
        live = [_key(r) for r in live_rules]
        target = f"{net_name} / L3 outbound rules"

        extra_idx = [i for i, k in enumerate(live) if k not in expected_by_key]
        missing = [k for k in expected if k not in live]

        for index in extra_idx:
            rule, key = live_rules[index], live[index]
            shadowed = [
                expected_by_key[later]
                for later in live[index + 1:]
                if later in expected_by_key and _shadows(key, later)
            ]
            if shadowed:
                findings.append(_shadow_finding(net_name, target, index, rule, shadowed))
            elif key[0] == "allow":
                findings.append(_extra_allow_finding(net_name, target, index, rule, key))
            else:
                findings.append(
                    Finding(
                        category=CAT_FIREWALL, check=CHECK_NAME, severity=LOW,
                        network=net_name, target=target,
                        finding="Deny rule present that is not part of the standard.",
                        evidence=f"Rule #{index + 1}: {_describe(rule)}.",
                        risk=(
                            "Extra deny rules are not a security exposure, but undocumented "
                            "blocks are a common cause of 'works at one site, not another' "
                            "tickets that take hours to trace."
                        ),
                        remediation=(
                            "Either add the rule to the baseline with a reason, or remove it: "
                            "Dashboard > Security & SD-WAN > Firewall > Outbound rules."
                        ),
                    )
                )

        for key in missing:
            rule = expected_by_key[key]
            is_deny = key[0] == "deny"
            findings.append(
                Finding(
                    category=CAT_FIREWALL, check=CHECK_NAME,
                    severity=HIGH if is_deny else LOW,
                    network=net_name, target=target,
                    finding=(
                        f"Baseline {'deny' if is_deny else 'allow'} rule is missing: "
                        f"'{rule.get('comment') or _describe(rule)}'."
                    ),
                    evidence=(
                        f"Expected rule {_describe(rule)} was not found among the "
                        f"{len(live_rules)} non-default outbound rules on this MX."
                    ),
                    risk=(
                        "The segmentation this rule enforces is absent at this site. "
                        "Because the MX default rule allows everything, a missing deny "
                        "means the traffic it was meant to stop flows freely."
                        if is_deny else
                        "Traffic the standard explicitly permits is relying on the "
                        "default rule. Harmless today, but it breaks the moment a broader "
                        "deny is added above it."
                    ),
                    remediation=(
                        "Add the rule in its baseline position: Dashboard > Security & "
                        "SD-WAN > Firewall > Outbound rules > Add a rule."
                    ),
                )
            )

        # Order drift among baseline rules that ARE present.
        present_in_live_order = [k for k in live if k in expected_by_key]
        present_in_baseline_order = [k for k in expected if k in present_in_live_order]
        if present_in_live_order != present_in_baseline_order:
            findings.append(
                Finding(
                    category=CAT_FIREWALL, check=CHECK_NAME, severity=MEDIUM,
                    network=net_name, target=target,
                    finding="Baseline firewall rules are present but in a different order.",
                    evidence=(
                        "Live order: "
                        + " > ".join(expected_by_key[k].get("comment") or k[0] for k in present_in_live_order)
                        + ". Baseline order: "
                        + " > ".join(expected_by_key[k].get("comment") or k[0] for k in present_in_baseline_order)
                        + "."
                    ),
                    risk=(
                        "The MX applies the first matching rule. Reordering can change "
                        "which rule wins for overlapping traffic, so the same rule set can "
                        "enforce a different policy at this site."
                    ),
                    remediation=(
                        "Drag the rules back into baseline order in Dashboard > Security & "
                        "SD-WAN > Firewall > Outbound rules."
                    ),
                )
            )

    return findings


# ------------------------------------------------------------------ findings


def _shadow_finding(net_name, target, index, rule, shadowed) -> Finding:
    names = ", ".join(f"'{s.get('comment') or _describe(s)}'" for s in shadowed)
    return Finding(
        category=CAT_FIREWALL, check=CHECK_NAME, severity=HIGH,
        network=net_name, target=target,
        finding=(
            f"A non-standard {rule.get('policy')} rule above the baseline overrides "
            f"{names}, so the baseline rule never takes effect."
        ),
        evidence=(
            f"Rule #{index + 1}: {_describe(rule)}"
            + (f" (comment: '{rule.get('comment')}')" if rule.get("comment") else "")
            + f". It matches all traffic that the later baseline rule {names} matches, "
            "and the MX stops evaluating at the first match."
        ),
        risk=(
            "This is the most dangerous kind of firewall drift because it is invisible "
            "in review: the baseline rule is still there, correctly written, and anyone "
            "checking for it will find it. It simply never runs. Temporary rules added "
            "during migrations are the usual cause, and they are rarely removed."
        ),
        remediation=(
            "Confirm with the change owner whether the rule is still needed. If not, "
            "delete it. If it is, narrow it to the specific source, destination and "
            "port required and move it below the baseline rule it overrides: Dashboard "
            "-> Security & SD-WAN > Firewall > Outbound rules."
        ),
        metadata={"rule_index": index + 1},
    )


def _extra_allow_finding(net_name, target, index, rule, key: RuleKey) -> Finding:
    _, _protocol, src, _sport, dst, dport = key
    if dst == "any" and dport == "any":
        severity, breadth = HIGH, "to any destination on any port"
    elif src == "any" and dst == "any":
        severity, breadth = MEDIUM, f"from any source to any destination on port {dport}"
    else:
        severity, breadth = LOW, "with a specific scope"
    return Finding(
        category=CAT_FIREWALL, check=CHECK_NAME, severity=severity,
        network=net_name, target=target,
        finding=f"Allow rule not in the standard, {breadth}.",
        evidence=(
            f"Rule #{index + 1}: {_describe(rule)}"
            + (f" (comment: '{rule.get('comment')}')" if rule.get("comment") else "")
            + "."
        ),
        risk=(
            "Every rule outside the standard is a decision nobody re-reviews. Broad "
            "allows are how one site ends up materially more exposed than the others "
            "while still appearing to follow the same policy."
            if severity != LOW else
            "A narrowly-scoped allow is low risk, but an undocumented one means the "
            "baseline no longer describes this site, and the next review has to work "
            "out from scratch why it exists."
        ),
        remediation=(
            "Either adopt it into the baseline with an owner and a reason, or remove it. "
            "If it must stay, narrow source and destination to the specific hosts "
            "involved: Dashboard > Security & SD-WAN > Firewall > Outbound rules."
        ),
        metadata={"rule_index": index + 1},
    )


# ------------------------------------------------------------------- helpers


def _norm(value: Any) -> str:
    text = str(value if value is not None else "any").strip().lower().replace(" ", "")
    return "any" if text in ("", "any", "*") else text


def _key(rule: Dict[str, Any]) -> RuleKey:
    return tuple(_norm(rule.get(f, "any")) for f in FIELDS)  # type: ignore[return-value]


def _strip_default(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop the trailing implicit default rule Dashboard appends to every list."""
    if rules and (
        str(rules[-1].get("comment", "")).lower() == "default rule"
        or _key(rules[-1]) == ("allow", "any", "any", "any", "any", "any")
    ):
        return rules[:-1]
    return list(rules)


def _covers_value(a: str, b: str) -> bool:
    if a == "any" or a == b:
        return True
    if b == "any":
        return False
    a_items, b_items = a.split(","), b.split(",")
    return all(any(_covers_item(x, y) for x in a_items) for y in b_items)


def _covers_item(a: str, b: str) -> bool:
    if a == b:
        return True
    net_a, net_b = _as_network(a), _as_network(b)
    if net_a is not None and net_b is not None and net_a.version == net_b.version:
        return net_b.subnet_of(net_a)  # type: ignore[arg-type]
    return False


def _as_network(text: str) -> Optional[Any]:
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None  # VLAN(30).*, FQDNs, object groups: compared by equality only


def _shadows(earlier: RuleKey, later: RuleKey) -> bool:
    """True if `earlier` matches all traffic `later` does, with the opposite verdict."""
    if earlier[0] == later[0]:
        return False
    return all(_covers_value(e, l) for e, l in zip(earlier[1:], later[1:]))


def _describe(rule: Dict[str, Any]) -> str:
    return (
        f"{str(rule.get('policy', '')).upper()} {rule.get('protocol', 'any')} "
        f"{rule.get('srcCidr', 'Any')}:{rule.get('srcPort', 'Any')} -> "
        f"{rule.get('destCidr', 'Any')}:{rule.get('destPort', 'Any')}"
    )
