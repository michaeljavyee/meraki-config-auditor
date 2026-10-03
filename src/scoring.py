"""The Finding model, severity vocabulary, and shared helpers.

Everything a check produces flows through here, so adding a check needs no
changes to the report, the CSV writer, or the terminal output.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------- severity

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

# Severity is about consequence, not about how far the config is from the
# baseline. A one-character difference in an allowed-VLAN list can be an
# outage; a dozen differences in band-steering settings are a tidy-up.
SEVERITY_DEFINITIONS = {
    CRITICAL: (
        "Breaking something now. Devices or users are without connectivity, or "
        "a control the business relies on is absent, as a direct result of this "
        "configuration. Fix in the next change window, within 24 hours."
    ),
    HIGH: (
        "A security boundary is weakened or bypassed (segmentation, wireless "
        "authentication, firewall policy), or a misconfiguration will cause an "
        "outage under conditions that occur routinely. Fix within 30 days."
    ),
    MEDIUM: (
        "Drift from the standard that is not currently harmful but will cause a "
        "failure or a gap the next time something changes: a new device is "
        "plugged in, a link fails over, a firmware feature is relied on. "
        "Fix this quarter."
    ),
    LOW: (
        "Consistency and hygiene. The site works and is not exposed, but differs "
        "from the standard in ways that make troubleshooting and change slower."
    ),
    INFO: "Inventory context with no finding attached.",
}

SEVERITY_TIMEFRAME = {
    CRITICAL: "Next change window (24 hours)",
    HIGH: "This month (30 days)",
    MEDIUM: "This quarter (90 days)",
    LOW: "Backlog / next standards review",
    INFO: "No action required",
}

# ---------------------------------------------------------------- categories

CAT_VLAN_TRUNK = "vlan_trunk"
CAT_FIREWALL = "firewall"
CAT_SSID = "ssid"
CAT_FIRMWARE = "firmware"
CAT_IPAM = "ipam"

CATEGORY_LABELS = {
    CAT_VLAN_TRUNK: "VLAN / 802.1Q trunk",
    CAT_FIREWALL: "L3 firewall policy",
    CAT_SSID: "Wireless SSID",
    CAT_FIRMWARE: "Firmware",
    CAT_IPAM: "Address space (IPAM)",
}


@dataclass
class Finding:
    """One audit result.

    The last four text fields separate a deliverable from a log dump:

      finding     - what is wrong (one line, factual)
      evidence    - the specific config that proves it, quoted from the API
      risk        - why the business should care, in plain language
      remediation - the exact change, naming the Dashboard path
    """

    category: str
    target: str
    severity: str
    finding: str
    evidence: str
    risk: str
    remediation: str
    network: str = ""
    device: str = ""
    check: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError(
                f"Unknown severity {self.severity!r} on {self.target!r}. "
                f"Use one of: {', '.join(SEVERITY_ORDER)}"
            )
        if self.category not in CATEGORY_LABELS:
            raise ValueError(
                f"Unknown category {self.category!r}. Use one of: "
                f"{', '.join(CATEGORY_LABELS)}"
            )

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS[self.category]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InventoryItem:
    """One device, findings aside. The inventory stands on its own."""

    network: str
    name: str
    serial: str
    model: str
    product_type: str
    firmware: str
    lan_ip: str = ""
    finding_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (f.rank, f.network, f.category, f.target))


def count_by_severity(findings: List[Finding]) -> Dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


# ------------------------------------------------------------ VLAN list parsing

MAX_VLAN = 4094


class VlanSet:
    """A set of 802.1Q VLAN IDs parsed from Meraki's `allowedVlans` string.

    Meraki expresses trunk membership as a string: "all", "1,10,20-25", or
    "1-4094". "all" is common and must not be expanded into 4094 integers just
    to answer "is 40 in here?", so it is represented as a flag.
    """

    def __init__(self, ids: Optional[Set[int]] = None, all_vlans: bool = False) -> None:
        self.ids: Set[int] = set(ids or ())
        self.all = all_vlans

    @classmethod
    def parse(cls, value: Any) -> "VlanSet":
        if value is None:
            return cls()
        text = str(value).strip().lower()
        if text in ("", "none"):
            return cls()
        if text == "all":
            return cls(all_vlans=True)
        ids: Set[int] = set()
        for part in text.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo_text, hi_text = part.split("-", 1)
                lo, hi = int(lo_text), int(hi_text)
                if lo > hi:
                    lo, hi = hi, lo
                if lo <= 1 and hi >= MAX_VLAN:
                    return cls(all_vlans=True)
                ids.update(range(lo, hi + 1))
            else:
                ids.add(int(part))
        return cls(ids)

    def __contains__(self, vlan: int) -> bool:
        return self.all or vlan in self.ids

    def missing(self, required: Set[int]) -> Set[int]:
        if self.all:
            return set()
        return set(required) - self.ids

    def __repr__(self) -> str:  # pragma: no cover
        return "VlanSet(all)" if self.all else f"VlanSet({format_vlans(self.ids)})"


def format_vlans(vlans: Set[int]) -> str:
    """Render {1,2,3,10} as "1-3,10" - the same notation Dashboard uses."""
    ordered = sorted(vlans)
    if not ordered:
        return "none"
    parts: List[str] = []
    start = prev = ordered[0]
    for vid in ordered[1:]:
        if vid == prev + 1:
            prev = vid
            continue
        parts.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = vid
    parts.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(parts)


def plural(count: int, word: str, suffix: str = "s") -> str:
    return f"{count} {word}{'' if count == 1 else suffix}"
