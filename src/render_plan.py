"""Render a Plan as terminal text, Markdown (for a pull-request comment), or JSON."""

from __future__ import annotations

import json
from typing import Any, List

from .diff import CREATE, DELETE, SYMBOL, UPDATE, Plan, describe_rule

FOOTER = (
    "This plan was computed read-only. Nothing was changed, and this tool has no "
    "apply: make the change in Dashboard (or your change process), then run plan "
    "again to confirm it shows no changes."
)


def summary_line(plan: Plan) -> str:
    if not plan.has_changes:
        return "No changes. Live configuration matches the intent."
    return (
        f"Plan: {plan.count(CREATE)} to add, {plan.count(UPDATE)} to change, "
        f"{plan.count(DELETE)} to destroy."
    )


def render_text(plan: Plan) -> str:
    """Plain text with +/~/- markers. Diff-friendly; also what Markdown wraps."""
    lines: List[str] = [
        f"Meraki plan for {plan.org_name}",
        f"Intent: {plan.intent_source}",
        f"Networks: {', '.join(plan.networks) or 'none'}",
        "",
    ]
    for change in plan.changes:
        symbol = SYMBOL[change.action]
        label = f"   # {change.label}" if change.label else ""
        lines.append(f"{symbol} {change.address}{label}")
        width = max((len(a.attr) for a in change.attrs), default=0)
        for a in change.attrs:
            if change.action == CREATE:
                lines.append(f"    + {a.attr.ljust(width)} = {_fmt(a.new)}")
            elif change.action == DELETE:
                lines.append(f"    - {a.attr.ljust(width)} = {_fmt(a.old)}")
            else:
                note = f"   ({a.note})" if a.note else ""
                lines.append(f"    ~ {a.attr.ljust(width)} : {_fmt(a.old)} -> {_fmt(a.new)}{note}")
        for r in change.rules:
            where = "was" if r.op == "-" else "at"
            lines.append(f"    {r.op} [{where} #{r.position}] {describe_rule(r.rule)}")
        lines.append("")

    for error in plan.errors:
        lines.append(f"! error: {error}")
    if plan.errors:
        lines.append("")
    lines.append(summary_line(plan))
    return "\n".join(lines)


def render_markdown(plan: Plan) -> str:
    """For a PR comment: GitHub colours ```diff blocks by their leading +/-."""
    body = render_text(plan)
    # In a diff block "~" isn't coloured; prefix updates with "!" so they stand out.
    diff_lines = [("!" + line[1:]) if line.startswith("~ ") else line for line in body.splitlines()]
    return (
        f"### Meraki plan: {plan.org_name}\n\n"
        f"**{summary_line(plan)}**\n\n"
        "```diff\n" + "\n".join(diff_lines) + "\n```\n\n"
        f"_{FOOTER}_\n"
    )


def render_json(plan: Plan) -> str:
    return json.dumps(plan.to_dict(), indent=2, default=str)


def print_terminal(plan: Plan) -> None:
    """render_text, coloured when rich is available and stdout is a terminal."""
    text = render_text(plan)
    try:
        from rich.console import Console
        from rich.markup import escape
    except ImportError:  # pragma: no cover
        print(text)
        print("\n" + FOOTER)
        return
    console = Console()
    styles = {"+": "green", "-": "red", "~": "yellow", "!": "bold red"}
    for line in text.splitlines():
        marker = line.strip()[:1]
        style = styles.get(marker)
        if line.startswith("Plan:") or line.startswith("No changes"):
            style = "bold"
        console.print(f"[{style}]{escape(line)}[/]" if style else escape(line), highlight=False)
    console.print(f"\n[dim]{escape(FOOTER)}[/]", highlight=False)


def _fmt(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_fmt(v) for v in value) + "]"
    return f'"{value}"'
