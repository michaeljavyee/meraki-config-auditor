"""Compare declared intent with live configuration and print the difference.

    python -m src.plan --demo
    python -m src.plan --intent intent/ --format markdown > plan.md

Like `terraform plan`, and deliberately without the other half. The output
tells you what would have to change for the network to match the file; it
does not change it. See docs/config-as-code.md for why there is no `apply`.

Exit codes follow `terraform plan -detailed-exitcode`, so the plan can gate a
pipeline or a scheduled drift check:

    0  no changes: live matches intent
    1  error: the intent references something that doesn't exist, or the
       intent file is invalid
    2  changes present
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from .audit import DEFAULT_BASELINE, ROOT, build_client, choose_org
from .baseline import load_baseline
from .checks.base import OrgContext
from .diff import compute_plan
from .intent import IntentError, load_intent
from .render_plan import print_terminal, render_json, render_markdown, render_text  # noqa: F401

DEMO_INTENT = ROOT / "intent" / "demo" / "cedar-valley.yaml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.plan",
        description=(
            "Show what would have to change for live Meraki configuration to match a "
            "declared intent file. Read-only; there is no apply."
        ),
    )
    parser.add_argument("--demo", action="store_true",
                        help="plan the bundled demo intent against the demo org")
    parser.add_argument("--intent", type=Path, default=None,
                        help="intent YAML file or directory (default with --demo: intent/demo/cedar-valley.yaml)")
    parser.add_argument("--org-id", default=None, help="organization ID (or MERAKI_ORG_ID)")
    parser.add_argument("--format", choices=["terminal", "text", "markdown", "json"], default="terminal")
    parser.add_argument("--output", type=Path, default=None, help="write to a file instead of stdout")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def _display_path(path: Path) -> Path:
    """Relative to the working directory when possible: it's printed in the plan."""
    try:
        return Path(path).resolve().relative_to(Path.cwd())
    except ValueError:
        return Path(path)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    intent_path = args.intent or (DEMO_INTENT if args.demo else None)
    if intent_path is None:
        print("Specify --intent (create one with `python -m src.export`), or use --demo.",
              file=sys.stderr)
        return 1
    try:
        intent = load_intent(_display_path(intent_path))
    except IntentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    client, orgs, _source = build_client(args.demo)
    org = choose_org(orgs, args.org_id or os.environ.get("MERAKI_ORG_ID", "").strip() or None)
    context = OrgContext(client, org, load_baseline(DEFAULT_BASELINE))
    try:
        plan = compute_plan(context, intent)
    finally:
        client.close()

    if args.format == "terminal" and not args.output:
        print_terminal(plan)
    else:
        renderer = {"terminal": render_text, "text": render_text,
                    "markdown": render_markdown, "json": render_json}[args.format]
        text = renderer(plan)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text + "\n")
            print(f"wrote {args.output}", file=sys.stderr)
        else:
            print(text)

    if plan.errors:
        return 1
    return 2 if plan.has_changes else 0


if __name__ == "__main__":
    raise SystemExit(main())
