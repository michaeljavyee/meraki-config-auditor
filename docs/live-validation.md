# Live validation

## 2026-10-02: Cisco DevNet Meraki Sandbox

First run against a real Meraki organization, after v0.1 had only been
tested against fixtures and mocked API responses.

**Target.** A reserved DevNet "Meraki Sandbox" organization: one network
(`branch_office`) with four virtual devices (MX100, MS250-24, MR52, MV12W),
read-only access. Audited against `baselines/example.yaml`, which describes a
different, fictional company, so drift was expected.

**Result.** Full pipeline completed against the live Dashboard API with no
errors: org selection, pagination, every check, and HTML/CSV/terminal output.

| Severity | Count | What |
|---|---|---|
| High | 2 | Both baseline deny rules absent (the MX had no outbound rules at all) |
| Medium | 3 | Both standard SSIDs absent; one enabled SSID outside the standard |
| Low | 5 | Missing baseline allow rule; four devices not running configured firmware |

**What the live run taught us (and what changed):**

1. **The key could see two organizations** (the sandbox and a personal org).
   The tool refused to guess and listed both, as designed. Choosing the wrong
   org would produce a confident, wrong report.
2. **Virtual devices report firmware as the literal string
   `Not running configured version`.** v0.1 reported that as "could not be
   compared", which was accurate but unhelpful. It now gets its own finding
   that says what the state means and what to check.
3. **The switch's trunk ports were not tagged or named as uplinks**, so the
   VLAN/trunk check recorded a scope limitation rather than guessing which
   port was the uplink. Correct behavior, but it means the flagship check
   didn't run on this org. Identifying uplinks from LLDP topology as a
   fallback is the next improvement to that check.
4. **Devices had no names**, so findings fell back to serial numbers.

Reports from this run are not committed: they're generated output, and
`reports/` is gitignored apart from the demo sample.
