"""Check 4 - firmware version drift.

Mixed firmware is one of the least visible causes of strange network
behaviour. Two switches on different major versions can disagree on STP
handling, LLDP fields, or feature defaults; a single replaced switch shipped
from the depot on old firmware is the common case after a hardware swap.
Meraki makes upgrades easy, which makes it easy to assume everything is current.

For each device, compares the running firmware with the baseline target for
its product type:

  different major version from the target                MEDIUM
  same major but behind, while network peers are on the
    target (mixed versions within one site)              MEDIUM
  same major, behind, consistent with its peers          LOW
  ahead of the target (beta / unapproved)                LOW
  firmware string not parseable                          LOW

Firmware strings look like "switch-17-1-4" or "wired-18-2-11"; the numeric
parts are compared as a version tuple.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from ..scoring import CAT_FIRMWARE, LOW, MEDIUM, Finding
from .base import OrgContext, product_type_of

CHECK_NAME = "firmware_drift"

Version = Tuple[int, ...]

NOT_RUNNING_CONFIGURED = "not running configured version"


def parse_version(firmware: Any) -> Optional[Version]:
    if not firmware:
        return None
    numbers = re.findall(r"\d+", str(firmware))
    return tuple(int(n) for n in numbers) if numbers else None


def run(context: OrgContext) -> List[Finding]:
    findings: List[Finding] = []
    targets = context.baseline.firmware
    if not targets:
        context.note_limitation("The baseline defines no firmware targets; firmware was not assessed.")
        return findings

    in_scope = {n["id"]: n for n in context.networks}
    by_net_product: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for device in context.devices:
        if device.get("networkId") in in_scope:
            by_net_product[(device["networkId"], product_type_of(device))].append(device)

    for (net_id, product), devices in sorted(by_net_product.items()):
        target_text = targets.get(product)
        if not target_text:
            continue
        target = parse_version(target_text)
        net_name = in_scope[net_id].get("name", net_id)
        peer_versions = {d.get("firmware") for d in devices}
        mixed = len(peer_versions) > 1

        for device in sorted(devices, key=lambda d: d.get("name") or ""):
            running_text = device.get("firmware")
            if running_text == target_text:
                continue
            name = device.get("name") or device.get("serial")
            running = parse_version(running_text)
            base = dict(
                category=CAT_FIRMWARE, check=CHECK_NAME, network=net_name, device=name,
                target=f"{net_name} / {name}",
                metadata={"running": running_text, "target": target_text, "product": product},
            )
            evidence = (
                f"{name} ({device.get('model')}, {device.get('serial')}) runs "
                f"'{running_text}'. Baseline target for {product}: '{target_text}'. "
                f"{product.capitalize()} versions in {net_name}: "
                f"{', '.join(sorted(str(v) for v in peer_versions))}."
            )
            tags = device.get("tags") or []
            if tags:
                evidence += f" Device tags: {', '.join(tags)}."

            if str(running_text).strip().lower() == NOT_RUNNING_CONFIGURED:
                # Dashboard's literal value when a device has never applied
                # the firmware its network is configured for: typically a
                # unit that was never brought online, is offline, or is
                # mid-upgrade. Seen first on a live DevNet sandbox org.
                findings.append(Finding(
                    severity=LOW, **base,
                    finding="Device is not running its network's configured firmware.",
                    evidence=evidence,
                    risk=(
                        "Dashboard reports this device has not applied the firmware its "
                        "network is configured for. Usually the device has never checked "
                        "in, is offline, or an upgrade is pending. Its actual version is "
                        "unknown, so it can't be compared with the baseline."
                    ),
                    remediation=(
                        "Confirm the device is online and checking in to Dashboard, then "
                        "review Organization > Firmware upgrades for a pending or failed "
                        "upgrade. Re-run this audit once it reports a version."
                    ),
                ))
                continue

            if running is None or target is None:
                findings.append(Finding(
                    severity=LOW, **base,
                    finding="Firmware version could not be compared with the baseline.",
                    evidence=evidence,
                    risk="The device's firmware state is unknown to this audit.",
                    remediation="Check the device in Dashboard > Organization > Firmware upgrades.",
                ))
                continue

            if running > target:
                findings.append(Finding(
                    severity=LOW, **base,
                    finding=f"Running firmware ahead of the approved version ({running_text}).",
                    evidence=evidence,
                    risk=(
                        "Usually a beta or early-release build. Fine for a deliberate pilot, "
                        "but if it isn't one, this device is running code nobody approved "
                        "and support may ask you to roll back before troubleshooting."
                    ),
                    remediation=(
                        "If this is an intentional pilot, record it in the baseline. "
                        "Otherwise schedule a move to the approved version: Dashboard > "
                        "Organization > Firmware upgrades."
                    ),
                ))
                continue

            major_behind = running[:1] != target[:1]
            severity = MEDIUM if (major_behind or mixed) else LOW
            reason = (
                "a different major version" if major_behind
                else "behind its peers in the same network" if mixed
                else "behind the approved version"
            )
            findings.append(Finding(
                severity=severity, **base,
                finding=f"Firmware is {reason} ({running_text}, target {target_text}).",
                evidence=evidence,
                risk=(
                    "Devices that should behave identically don't. Mixed firmware "
                    "within one site produces the hardest kind of fault: a feature "
                    "or default that works on one switch and not the next, with "
                    "identical configuration on both. A replacement unit shipped on "
                    "old firmware after a hardware swap is the usual cause."
                    if severity == MEDIUM else
                    "Missing fixes and security patches in the approved release. "
                    "Low urgency while the site is internally consistent."
                ),
                remediation=(
                    f"Schedule {name} for '{target_text}': Dashboard > Organization > "
                    "Firmware upgrades > select the device > Schedule upgrade. Add "
                    "'upgrade to baseline firmware' to the hardware-replacement checklist."
                ),
            ))

    return findings
