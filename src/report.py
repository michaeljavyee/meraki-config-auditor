"""Output renderers: HTML deliverable, CSV, and terminal summary.

The HTML report is the product: it's what gets handed to a network owner or
attached to a change ticket. The terminal output is for the person running
the audit; the CSV is for tracking remediation in a spreadsheet.
"""

from __future__ import annotations

import csv
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__
from .baseline import Baseline
from .scoring import (
    CATEGORY_LABELS,
    CATEGORY_SHORT,
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    SEVERITY_DEFINITIONS,
    SEVERITY_ORDER,
    SEVERITY_TIMEFRAME,
    Finding,
    InventoryItem,
    count_by_severity,
    plural,
)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

SCOPE_COVERED = [
    "Uplink trunk allowed-VLAN lists against VLANs in use on each switch's access ports",
    "Uplink trunk allowed-VLAN lists against the baseline's required VLANs",
    "Native VLAN agreement across both ends of each discovered link, and against the baseline",
    "MX L3 outbound firewall rules against the baseline policy, including rule order and shadowing",
    "SSID authentication, encryption, VLAN and radio settings against the baseline",
    "Running firmware per device against the baseline target for its product type",
    "VLAN subnets for overlap within and between networks",
    "DHCP pools against reserved ranges, fixed reservations and clients seen in the last 7 days",
    "Fixed reservations that can't be served, are held by another device, or are for devices no longer seen",
    "Clients using addresses outside every subnet in their network",
    "802.1X access policy design: host mode, guest / failed-auth and fail-open VLANs, RADIUS redundancy and accounting",
    "Access ports that enforce no access policy and aren't tagged exempt",
    "How wired clients on enforcing ports were admitted: 802.1X, MAB, or the failed-auth VLAN",
]

SCOPE_EXCLUDED = [
    "Switch access-port configuration drift (port security, 802.1X, STP guard) - planned",
    "DNS, IPv6, and address space managed outside Meraki (external DHCP servers, data centre)",
    "RADIUS server configuration, certificates, and policies applied by RADIUS (dynamic VLANs, ACLs)",
    "Wireless 802.1X (covered by the SSID check's authentication mode only)",
    "Orphaned or unused configuration objects (policy objects, group policies) - planned",
    "Inbound firewall rules, port forwarding, 1:1 NAT, L7 and content filtering",
    "Site-to-site VPN, SD-WAN and routing configuration",
    "Live traffic, client data, and anything requiring packet capture",
    "Configuration outside Meraki Dashboard (ISP equipment, third-party switches)",
    "Any change to configuration. This tool cannot write.",
]


def render_html(
    findings: List[Finding],
    inventory: List[InventoryItem],
    networks: List[Dict[str, Any]],
    output_path: Path,
    org_name: str,
    baseline: Baseline,
    source: str,
    demo: bool = False,
    scope_limitations: Optional[List[str]] = None,
    address_space: Optional[List[Dict[str, Any]]] = None,
    nac_posture: Optional[List[Dict[str, Any]]] = None,
) -> Path:
    """Render the self-contained HTML report.

    autoescape is on: port names, SSID names and rule comments come straight
    from the customer's Dashboard, and a port named `<script>` must render as
    text.
    """
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html.j2")
    counts = count_by_severity(findings)

    rendered = template.render(
        org_name=org_name,
        source=source,
        version=__version__,
        generated_at=datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC"),
        demo=demo,
        baseline=baseline,
        findings=findings,
        inventory=inventory,
        site_matrix=build_site_matrix(findings, networks, inventory),
        category_labels=CATEGORY_LABELS,
        category_short=CATEGORY_SHORT,
        counts=counts,
        verdict=build_verdict(findings, networks, counts),
        roadmap=build_roadmap(findings),
        severity_definitions=SEVERITY_DEFINITIONS,
        scope_covered=SCOPE_COVERED,
        scope_excluded=SCOPE_EXCLUDED,
        scope_limitations=scope_limitations or [],
        address_space=address_space or [],
        nac_posture=nac_posture or [],
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    return output_path


def build_site_matrix(
    findings: List[Finding], networks: List[Dict[str, Any]], inventory: List[InventoryItem]
) -> List[Dict[str, Any]]:
    """One row per network: device count, findings per category, worst severity."""
    rows = []
    for network in networks:
        name = network.get("name", network["id"])
        mine = [f for f in findings if f.network == name]
        per_cat: Dict[str, List[Finding]] = {c: [] for c in CATEGORY_LABELS}
        for finding in mine:
            per_cat[finding.category].append(finding)
        cells = OrderedDict()
        for category, items in per_cat.items():
            worst = min((f.rank for f in items), default=None)
            cells[category] = {
                "count": len(items),
                "worst": SEVERITY_ORDER[worst] if worst is not None else "",
            }
        worst_overall = min((f.rank for f in mine), default=None)
        rows.append({
            "name": name,
            "tags": network.get("tags") or [],
            "devices": sum(1 for i in inventory if i.network == name),
            "cells": cells,
            "total": len(mine),
            "worst": SEVERITY_ORDER[worst_overall] if worst_overall is not None else "",
        })
    return rows


def build_verdict(
    findings: List[Finding], networks: List[Dict[str, Any]], counts: Dict[str, int]
) -> List[str]:
    """The paragraph a reader takes away if they read nothing else."""
    sites = plural(len(networks), "network")
    paragraphs: List[str] = []

    if counts[CRITICAL]:
        worst = next(f for f in findings if f.severity == CRITICAL)
        headline = (
            f"This audit compared {sites} against the declared standard and found "
            f"{plural(len(findings), 'deviation')}. "
            f"{plural(counts[CRITICAL], 'finding')} "
            f"{'is' if counts[CRITICAL] == 1 else 'are'} breaking something now. The most significant is at {worst.network}: "
            f"{worst.finding}"
        )
    elif counts[HIGH]:
        headline = (
            f"This audit compared {sites} against the declared standard and found "
            f"{plural(len(findings), 'deviation')}. Nothing is causing an outage, but "
            f"{plural(counts[HIGH], 'finding')} weaken a security boundary."
        )
    elif findings:
        headline = (
            f"This audit compared {sites} against the declared standard and found "
            f"{plural(len(findings), 'deviation')}, none of which is breaking anything "
            "or weakening a security boundary today."
        )
    else:
        headline = f"This audit compared {sites} against the declared standard and found no drift."
    paragraphs.append(headline)

    by_site = Counter(f.network for f in findings)
    if len(by_site) > 1:
        ranked = by_site.most_common()
        (top, top_n), (_, second_n) = ranked[0], ranked[1]
        # Only claim concentration when it's real: a clear leader holding a
        # large share. A tie for first place is not a pattern.
        if top_n > second_n and top_n / len(findings) >= 0.4:
            paragraphs.append(
                f"Drift is not evenly spread. {top} accounts for {top_n} of the "
                f"{len(findings)} findings. Reviewing that site's recent changes as a "
                "whole is likely to be more productive than working through its "
                "findings one at a time."
            )

    if findings:
        paragraphs.append(
            "None of these findings needed privileged access or live traffic "
            "to detect. Every one is visible in Dashboard configuration and was "
            "found by comparing it against a written standard. Running this "
            "comparison before closing a network change, rather than after the "
            "next outage, is the main recommendation of this report."
        )
    return paragraphs


def build_roadmap(findings: List[Finding]) -> List[Dict[str, Any]]:
    titles = {
        CRITICAL: "Restore service",
        HIGH: "Close security gaps",
        MEDIUM: "Remove latent failures",
        LOW: "Standardise",
    }
    roadmap = []
    for severity in (CRITICAL, HIGH, MEDIUM, LOW):
        matching = [f for f in findings if f.severity == severity]
        if matching:
            roadmap.append({
                "severity": severity,
                "title": titles[severity],
                "timeframe": SEVERITY_TIMEFRAME[severity],
                "actions": [
                    {"summary": f"{f.target}: {f.finding}", "detail": _first_sentence(f.remediation)}
                    for f in matching
                ],
            })
    return roadmap


def _first_sentence(text: str) -> str:
    for delimiter in (". ", "? "):
        if delimiter in text:
            candidate = text.split(delimiter)[0] + delimiter.strip()
            if len(candidate) > 25:
                return candidate
    return text


# ------------------------------------------------------------------------ CSV

CSV_COLUMNS = [
    "severity", "category", "network", "device", "target", "check",
    "finding", "evidence", "risk", "remediation",
]


def write_csv(findings: List[Finding], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for finding in findings:
            row = finding.to_dict()
            writer.writerow({c: row.get(c, "") for c in CSV_COLUMNS})
    return output_path


def write_inventory_csv(inventory: List[InventoryItem], output_path: Path) -> Path:
    columns = ["network", "name", "serial", "model", "product_type", "firmware", "lan_ip", "finding_count"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for item in inventory:
            writer.writerow(item.to_dict())
    return output_path


# ------------------------------------------------------------------- terminal

SEVERITY_STYLES = {
    CRITICAL: "bold white on red",
    HIGH: "bold dark_orange",
    MEDIUM: "yellow",
    LOW: "green",
    "info": "blue",
}


def print_terminal(
    findings: List[Finding],
    inventory: List[InventoryItem],
    networks: List[Dict[str, Any]],
    org_name: str,
    baseline: Baseline,
    demo: bool = False,
) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
    except ImportError:  # pragma: no cover
        _print_plain(findings, org_name)
        return

    console = Console()
    counts = count_by_severity(findings)
    subtitle = "DEMO - bundled fixture data" if demo else "read-only audit"
    console.print()
    console.print(Panel(
        f"[bold]Meraki Configuration Drift Assessment[/bold]\n{org_name}\n"
        f"[dim]baseline: {baseline.name} ({baseline.version})[/dim]",
        subtitle=subtitle, expand=False,
    ))

    summary = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    summary.add_column("Severity")
    summary.add_column("Count", justify="right")
    for severity in (CRITICAL, HIGH, MEDIUM, LOW):
        summary.add_row(f"[{SEVERITY_STYLES[severity]}] {severity.upper()} [/]", str(counts[severity]))
    summary.add_row("[dim]networks / devices[/dim]", f"{len(networks)} / {len(inventory)}")
    console.print()
    console.print(summary)

    if not findings:
        console.print("\n[green]No drift from baseline.[/green]\n")
        return

    table = Table(show_header=True, header_style="bold", title="\nFindings",
                  title_justify="left", expand=True)
    table.add_column("Sev", width=10, no_wrap=True)
    table.add_column("Area", width=12)
    table.add_column("Where", width=34, overflow="fold")
    table.add_column("Finding", overflow="fold")
    for finding in findings:
        table.add_row(
            f"[{SEVERITY_STYLES[finding.severity]}] {finding.severity.upper()} [/]",
            finding.category, finding.target, finding.finding,
        )
    console.print(table)

    for finding in (f for f in findings if f.severity == CRITICAL):
        console.print()
        console.print(Panel(
            f"[bold]{finding.finding}[/bold]\n\n"
            f"[dim]Evidence:[/dim] {finding.evidence}\n\n"
            f"[dim]Fix:[/dim] {_first_sentence(finding.remediation)}",
            title=f"[bold white on red] CRITICAL [/] {finding.target}",
            border_style="red",
        ))
    console.print()


def _print_plain(findings: List[Finding], org_name: str) -> None:  # pragma: no cover
    print(f"\nMeraki Configuration Drift Assessment - {org_name}")
    for finding in findings:
        print(f"[{finding.severity.upper():>8}] {finding.target}: {finding.finding}")
