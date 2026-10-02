"""Check 3 - SSID configuration consistency across sites.

The same SSID name should mean the same thing everywhere. When "CVL-Corp" is
802.1X in one building and WPA2-PSK in another, or tags into VLAN 10 at HQ and
VLAN 1 at a depot, users and devices roam into a different security posture
without any visible change. And SSIDs that aren't in the standard at all -
installer networks, test SSIDs, a vendor's temporary network - tend to stay
enabled long after the reason for them is gone.

For each wireless network this compares every baseline SSID field-by-field
and flags enabled SSIDs that the baseline doesn't know about. Only fields the
baseline lists are compared, so the baseline decides what "consistent" means.

Severity is per field, by what the difference does:

  authMode                                   HIGH   (who can join)
  ipAssignmentMode, useVlanTagging,
  defaultVlanId / vlanId                     HIGH   (where their traffic lands)
  encryptionMode, wpaEncryptionMode          MEDIUM (strength of the link)
  everything else (band steering, bitrate)   LOW    (performance / hygiene)

  enabled SSID not in baseline, open auth    HIGH
  enabled SSID not in baseline, otherwise    MEDIUM
  baseline SSID missing / disabled           MEDIUM
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..scoring import CAT_SSID, HIGH, LOW, MEDIUM, SEVERITY_RANK, Finding
from .base import OrgContext

CHECK_NAME = "ssid_consistency"

FIELD_SEVERITY = {
    "authMode": HIGH,
    "ipAssignmentMode": HIGH,
    "useVlanTagging": HIGH,
    "defaultVlanId": HIGH,
    "vlanId": HIGH,
    "encryptionMode": MEDIUM,
    "wpaEncryptionMode": MEDIUM,
}

OPEN_AUTH_MODES = {"open", "open-enhanced"}


def run(context: OrgContext) -> List[Finding]:
    findings: List[Finding] = []
    standard = {s["name"]: s for s in context.baseline.ssids}
    if not standard:
        context.note_limitation("The baseline defines no SSIDs; SSID consistency was not assessed.")
        return findings

    for network in context.networks:
        if not context.has_product(network, "wireless"):
            continue
        net_name = network.get("name", network["id"])
        live = context.ssids(network["id"])
        live_by_name = {s.get("name"): s for s in live if s.get("enabled")}

        # --- baseline SSIDs: missing, or present with differences ------------
        for name, expected in standard.items():
            actual = live_by_name.get(name)
            target = f"{net_name} / SSID '{name}'"
            if actual is None:
                findings.append(
                    Finding(
                        category=CAT_SSID, check=CHECK_NAME, severity=MEDIUM,
                        network=net_name, target=target,
                        finding=f"Standard SSID '{name}' is not enabled at this site.",
                        evidence=(
                            f"No enabled SSID named '{name}' among the "
                            f"{len(live_by_name)} enabled SSIDs on {net_name}."
                        ),
                        risk=(
                            "Users and devices that roam between sites expect the same "
                            "network everywhere. Its absence usually means someone set up "
                            "a local substitute, which is then outside the standard."
                        ),
                        remediation=(
                            "Dashboard > Wireless > SSIDs: enable and configure "
                            f"'{name}' to the baseline."
                        ),
                    )
                )
                continue

            diffs = _diff(expected, actual)
            if not diffs:
                continue
            worst = min((FIELD_SEVERITY.get(f, LOW) for f, _, _ in diffs), key=SEVERITY_RANK.get)
            detail = "; ".join(f"{f}: expected '{e}', found '{a}'" for f, e, a in diffs)
            findings.append(
                Finding(
                    category=CAT_SSID, check=CHECK_NAME, severity=worst,
                    network=net_name, target=target,
                    finding=(
                        f"SSID '{name}' differs from the standard in "
                        f"{', '.join(f for f, _, _ in diffs)}."
                    ),
                    evidence=f"SSID #{actual.get('number')} on {net_name}. {detail}.",
                    risk=_risk_for(worst, name),
                    remediation=(
                        f"Dashboard > Wireless > Access control > SSID '{name}': set "
                        + ", ".join(f"{f} to '{e}'" for f, e, _ in diffs)
                        + ". Change authentication and VLAN settings in a maintenance "
                        "window; clients will reassociate."
                    ),
                    metadata={"fields": [f for f, _, _ in diffs]},
                )
            )

        # --- enabled SSIDs the baseline doesn't know about ---------------------
        for name, actual in live_by_name.items():
            if name in standard:
                continue
            auth = str(actual.get("authMode") or "")
            is_open = auth in OPEN_AUTH_MODES
            vlan = actual.get("defaultVlanId") or actual.get("vlanId")
            bridged = actual.get("ipAssignmentMode") == "Bridge mode"
            where = (
                f"bridged into {context.baseline.vlan_label(int(vlan))}"
                if bridged and vlan not in (None, "") else
                f"IP assignment '{actual.get('ipAssignmentMode')}'"
            )
            findings.append(
                Finding(
                    category=CAT_SSID, check=CHECK_NAME,
                    severity=HIGH if is_open else MEDIUM,
                    network=net_name, target=f"{net_name} / SSID '{name}'",
                    finding=(
                        f"Enabled SSID '{name}' is not part of the standard"
                        + (" and requires no authentication." if is_open else ".")
                    ),
                    evidence=(
                        f"SSID #{actual.get('number')} '{name}': enabled=true, "
                        f"authMode='{auth}', {where}, visible={actual.get('visible')}."
                    ),
                    risk=(
                        "Anyone within range can join this network without credentials"
                        + (f" and lands directly in {context.baseline.vlan_label(int(vlan))}"
                           if bridged and vlan not in (None, "") else "")
                        + ". Hiding the SSID (visible=false) does not prevent this; the "
                        "name is broadcast in probe responses. Installer and test SSIDs "
                        "like this are routinely left enabled after the work is finished."
                        if is_open else
                        "An SSID outside the standard has no defined owner or review "
                        "cycle. It may be legitimate, but nothing guarantees it will be "
                        "turned off when its purpose ends."
                    ),
                    remediation=(
                        f"If '{name}' is no longer needed, disable it: Dashboard > "
                        "Wireless > SSIDs. If it is, add it to the baseline with an owner "
                        "and move it off open authentication."
                    ),
                    metadata={"authMode": auth},
                )
            )

    return findings


def _diff(expected: Dict[str, Any], actual: Dict[str, Any]) -> List[tuple]:
    diffs = []
    for field_name, want in expected.items():
        if field_name == "name":
            continue
        have = actual.get(field_name)
        if _normalise(want) != _normalise(have):
            diffs.append((field_name, want, have))
    return diffs


def _normalise(value: Any) -> Any:
    if isinstance(value, str):
        return value.strip().lower()
    return value


def _risk_for(severity: str, name: str) -> str:
    if severity == HIGH:
        return (
            f"Clients joining '{name}' here get a different security posture than at "
            "other sites - a different authentication method or a different network "
            "segment - with no visible change on the device. Because the SSID name is "
            "identical, devices roam into it automatically."
        )
    if severity == MEDIUM:
        return (
            "The wireless link here is weaker than the standard. Allowing older "
            "encryption modes for compatibility keeps them available to everyone, "
            "including attackers who can force a downgrade."
        )
    return (
        "Not a security exposure. Inconsistent radio settings make performance "
        "complaints site-specific and harder to troubleshoot."
    )
