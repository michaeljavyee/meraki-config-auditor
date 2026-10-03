"""CLI entry point: load the baseline, run the checks, write the outputs.

    python -m src.audit --demo --format html

READ-ONLY GUARANTEE. Every network call in this program goes through
MerakiClient._get, which is hardcoded to HTTP GET. There is no POST, PUT or
DELETE anywhere in src/, and CI greps for them on every commit.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .baseline import Baseline, BaselineError, load_baseline
from .checks import firewall_drift, firmware_drift, ipam, ssid_consistency, vlan_trunks
from .checks.base import OrgContext, product_type_of
from .report import print_terminal, render_html, write_csv, write_inventory_csv
from .scoring import CRITICAL, HIGH, Finding, InventoryItem, sort_findings

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports"
DEFAULT_BASELINE = ROOT / "baselines" / "example.yaml"

# Order is the order findings are produced in; the report re-sorts by severity.
CHECKS = {
    "vlan_trunks": vlan_trunks.run,
    "firewall": firewall_drift.run,
    "ssids": ssid_consistency.run,
    "firmware": firmware_drift.run,
    "ipam": ipam.run,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.audit",
        description=(
            "Audit a Meraki organization's configuration against a declared "
            "baseline and report drift. Read-only: issues GET requests exclusively."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m src.audit --demo --format html\n"
            "  python -m src.audit --baseline baselines/mine.yaml --format all\n"
            "  python -m src.audit --checks vlan_trunks,firmware --fail-on critical\n"
        ),
    )
    parser.add_argument("--demo", action="store_true",
                        help="run against bundled fixtures; no Meraki account or network needed")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE,
                        help="baseline YAML to audit against (default: baselines/example.yaml)")
    parser.add_argument("--org-id", default=None,
                        help="organization ID (default: MERAKI_ORG_ID, or the only org the key sees)")
    parser.add_argument("--format", choices=["terminal", "html", "csv", "all"], default="terminal",
                        help="output format (default: terminal). 'all' writes html + csv too.")
    parser.add_argument("--output", type=Path, default=None,
                        help="output path stem for html/csv (default: reports/audit_demo or reports/audit_report)")
    parser.add_argument("--checks", default="all",
                        help=f"comma-separated subset of: {', '.join(CHECKS)} (default: all)")
    parser.add_argument("--fail-on", choices=["never", "critical", "high"], default="never",
                        help="exit 2 when findings at or above this severity exist; for CI/change gates")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser


def resolve_checks(argument: str) -> List[str]:
    if argument.strip().lower() == "all":
        return list(CHECKS)
    selected = [n.strip() for n in argument.split(",") if n.strip()]
    unknown = [n for n in selected if n not in CHECKS]
    if unknown:
        sys.exit(f"Unknown check(s): {', '.join(unknown)}\n  Available: {', '.join(CHECKS)}")
    return selected


def build_client(demo: bool) -> Tuple[Any, List[Dict[str, Any]], str]:
    """Return (client, visible organizations, human-readable source)."""
    if demo:
        from .demo_client import DemoClient

        client = DemoClient()
        return client, client.verify_connection(), "Bundled demo fixtures"

    from .meraki_client import MerakiClient, MerakiError

    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:  # pragma: no cover
        pass

    key = os.environ.get("MERAKI_API_KEY", "").strip()
    if not key:
        sys.exit(
            "Missing configuration.\n"
            "  Set MERAKI_API_KEY - copy .env.example to .env and fill it in.\n"
            "  Or run with no account at all:  python -m src.audit --demo --format html"
        )
    client = MerakiClient(key)
    try:
        orgs = client.verify_connection()
    except MerakiError as exc:
        sys.exit(f"\nCould not connect to the Meraki Dashboard API.\n\n{exc}\n")
    return client, orgs, "Meraki Dashboard API v1"


def choose_org(orgs: List[Dict[str, Any]], wanted: Optional[str]) -> Dict[str, Any]:
    if wanted:
        for org in orgs:
            if str(org.get("id")) == str(wanted):
                return org
        sys.exit(f"Organization {wanted} is not visible to this API key.\n" + _org_list(orgs))
    if len(orgs) == 1:
        return orgs[0]
    if not orgs:
        sys.exit("This API key cannot see any organizations.")
    # Refuse to guess. Auditing the wrong org produces a confident, wrong report.
    sys.exit(
        "This API key can see several organizations; choose one with --org-id or "
        "MERAKI_ORG_ID.\n" + _org_list(orgs)
    )


def _org_list(orgs: List[Dict[str, Any]]) -> str:
    return "\n".join(f"  {o.get('id'):>12}  {o.get('name')}" for o in orgs[:25])


def run_checks(context: OrgContext, selected: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for name in selected:
        logging.info("Check: %s", name)
        findings.extend(CHECKS[name](context))
    return sort_findings(findings)


def build_inventory(context: OrgContext, findings: List[Finding]) -> List[InventoryItem]:
    per_device = Counter(f.device for f in findings if f.device)
    in_scope = {n["id"]: n.get("name", n["id"]) for n in context.networks}
    items = [
        InventoryItem(
            network=in_scope[d["networkId"]],
            name=d.get("name") or d.get("serial", ""),
            serial=d.get("serial", ""),
            model=d.get("model", ""),
            product_type=product_type_of(d),
            firmware=d.get("firmware", ""),
            lan_ip=d.get("lanIp") or "",
            finding_count=per_device.get(d.get("name") or d.get("serial", ""), 0),
        )
        for d in context.devices
        if d.get("networkId") in in_scope
    ]
    return sorted(items, key=lambda i: (i.network, i.product_type, i.name))


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        baseline: Baseline = load_baseline(args.baseline)
    except BaselineError as exc:
        sys.exit(str(exc))
    selected = resolve_checks(args.checks)

    client, orgs, source = build_client(args.demo)
    org = choose_org(orgs, args.org_id or os.environ.get("MERAKI_ORG_ID", "").strip() or None)
    context = OrgContext(client, org, baseline)

    try:
        findings = run_checks(context, selected)
        inventory = build_inventory(context, findings)
        networks = context.networks
    finally:
        client.close()

    org_name = org.get("name", org.get("id"))

    if args.format in ("terminal", "all"):
        print_terminal(findings, inventory, networks, org_name, baseline, demo=args.demo)

    stem = Path(args.output or REPORTS_DIR / ("audit_demo" if args.demo else "audit_report"))
    written: List[Path] = []
    if args.format in ("html", "all"):
        written.append(render_html(
            findings=findings, inventory=inventory, networks=networks,
            output_path=stem.with_suffix(".html"), org_name=org_name, baseline=baseline,
            source=source, demo=args.demo, scope_limitations=context.scope_limitations,
            address_space=context.address_space,
        ))
    if args.format in ("csv", "all"):
        written.append(write_csv(findings, stem.with_suffix(".csv")))
        written.append(write_inventory_csv(
            inventory, stem.with_name(stem.name + "_inventory").with_suffix(".csv")))
    for path in written:
        print(f"wrote {path}")

    if args.fail_on == "critical" and any(f.severity == CRITICAL for f in findings):
        return 2
    if args.fail_on == "high" and any(f.severity in (CRITICAL, HIGH) for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
