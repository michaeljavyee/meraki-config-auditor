"""Snapshot live configuration as an intent file.

    python -m src.export --demo --output intent/snapshot.yaml
    python -m src.export --org-id 123 --networks HQ,Depot-West

This is how a network that was configured by hand becomes configuration as
code: export what is there today, commit it, and from then on every change is
an edit to the file, reviewed like any other change. `plan` reports anything
that drifts from it.

Read-only, like everything in src/. It reads through the same client and the
same OrgContext as the audit.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .audit import DEFAULT_BASELINE, build_client, choose_org
from .baseline import load_baseline
from .checks.base import OrgContext
from .state import read_network


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.export",
        description="Write live Meraki configuration as an intent YAML file. Read-only.",
    )
    parser.add_argument("--demo", action="store_true", help="export the bundled demo org")
    parser.add_argument("--org-id", default=None, help="organization ID (or MERAKI_ORG_ID)")
    parser.add_argument("--networks", default=None,
                        help="comma-separated network names to include (default: all)")
    parser.add_argument("--output", type=Path, default=None, help="file to write (default: stdout)")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def export_org(context: OrgContext, networks: Optional[List[str]] = None) -> Dict[str, Any]:
    by_name = {n.get("name"): n for n in context.all_networks}
    if networks:
        missing = [n for n in networks if n not in by_name]
        if missing:
            raise SystemExit(
                f"Network(s) not found: {', '.join(missing)}\n"
                f"  Available: {', '.join(sorted(n for n in by_name if n))}"
            )
        chosen = [by_name[n] for n in networks]
    else:
        chosen = sorted(context.all_networks, key=lambda n: n.get("name", ""))
    return {
        "organization": {"id": context.org_id, "name": context.org.get("name")},
        "networks": {n.get("name", n["id"]): read_network(context, n) for n in chosen},
    }


def dump_intent(data: Dict[str, Any], source: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = (
        f"# Exported from {source} at {stamp} by meraki-config-auditor.\n"
        "# This is the configuration as it IS. Edit it to describe how it SHOULD be,\n"
        "# commit it, and run `python -m src.plan` to see the difference.\n"
        "# Remove anything you don't want managed: only declared attributes are compared.\n"
    )
    return header + yaml.safe_dump(data, sort_keys=False, default_flow_style=False, width=100)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    client, orgs, source = build_client(args.demo)
    org = choose_org(orgs, args.org_id or os.environ.get("MERAKI_ORG_ID", "").strip() or None)
    # The baseline isn't used by export; OrgContext requires one for scoping.
    context = OrgContext(client, org, load_baseline(DEFAULT_BASELINE))
    wanted = [n.strip() for n in args.networks.split(",")] if args.networks else None

    try:
        text = dump_intent(export_org(context, wanted), source)
    finally:
        client.close()

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
