import csv

import pytest

from src import audit
from src.report import render_html
from src.scoring import CRITICAL, Finding


def test_demo_end_to_end(tmp_path):
    stem = tmp_path / "report"
    assert audit.main(["--demo", "--format", "all", "--output", str(stem)]) == 0
    html = (tmp_path / "report.html").read_text()
    assert "Configuration Drift Assessment" in html
    assert "Demonstration report" in html
    assert "SW-WEST-IDF1 port 8" in html
    with (tmp_path / "report.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["severity"] == "critical"
    assert (tmp_path / "report_inventory.csv").exists()


def test_fail_on_critical_exit_code(tmp_path):
    assert audit.main(["--demo", "--format", "csv", "--output", str(tmp_path / "r"),
                       "--fail-on", "critical"]) == 2


def test_check_subset(tmp_path):
    audit.main(["--demo", "--format", "csv", "--output", str(tmp_path / "r"), "--checks", "firmware"])
    with (tmp_path / "r.csv").open() as handle:
        assert {row["category"] for row in csv.DictReader(handle)} == {"firmware"}


def test_unknown_check_exits():
    with pytest.raises(SystemExit):
        audit.main(["--demo", "--checks", "dns"])


def test_choose_org_refuses_to_guess():
    with pytest.raises(SystemExit):
        audit.choose_org([{"id": "1"}, {"id": "2"}], None)
    assert audit.choose_org([{"id": "1"}, {"id": "2"}], "2")["id"] == "2"


def test_html_escapes_dashboard_strings(tmp_path, baseline):
    finding = Finding(category="vlan_trunk", target="<script>alert(1)</script>", severity=CRITICAL,
                      finding="x", evidence="y", risk="z", remediation="w", network="N")
    path = render_html([finding], [], [{"id": "N", "name": "N"}], tmp_path / "r.html",
                       "Org", baseline, "test")
    text = path.read_text()
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text
