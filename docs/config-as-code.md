# Network configuration as code

`export` and `plan` treat Meraki configuration the way Terraform treats
infrastructure: the intended state lives in version control, and a plan shows
how live state differs from it. This page explains the model and the
decisions behind it, including why there is no `apply`.

## The workflow

1. **Export** a network that was configured by hand:
   `python -m src.export --networks Depot-West --output intent/depot-west.yaml`
2. **Trim** the file to what you want managed. Delete desk ports, keep
   uplinks; delete PoE settings, keep VLANs. Only declared attributes are
   ever compared.
3. **Commit** it. From now on, a network change starts as an edit to this
   file, reviewed in a pull request like any other change.
4. **Plan** on every pull request (`--format markdown` makes the PR comment)
   and on a schedule (exit code 2 means drift appeared since the last run).
5. **Make the change** in Dashboard, through whatever change process applies,
   then plan again. An empty plan is the evidence the change matches what was
   approved.

## Intent vs. the audit baseline

| | Baseline (`baselines/`) | Intent (`intent/`) |
|---|---|---|
| Describes | A standard every network should meet | The exact configuration of specific networks |
| Compared | Loosely, by rule ("uplinks carry VLAN 40") | Exactly, attribute by attribute |
| Output | Findings with severity, risk and remediation | A plan: create / update / delete |
| Question | Is this network compliant? | Is it configured the way we said? |

They answer different questions and are useful together: the audit catches a
network that's wrong in a way nobody wrote down; the plan catches a network
that differs from what someone did write down.

## What can be managed

| Section | Keyed by | Can create | Can delete |
|---|---|---|---|
| `appliance_vlans` | VLAN ID | yes | only with `exclusive: [appliance_vlans]` |
| `l3_firewall_rules` | position (ordered list) | yes | yes; the list is exact |
| `switch_ports` | switch name or serial, then port ID | no; ports are physical | no |
| `ssids` | SSID number 0-14 | configures an unused slot | no; disable with `enabled: false` |

The attributes each section accepts are listed in `MANAGED_ATTRS` in
[`src/state.py`](../src/state.py). An unknown attribute is an error, not
something silently ignored, so a typo can't make a setting look managed when
it isn't.

## Comparison rules

- **Exact on declared attributes,** with three normalisations where Dashboard
  itself treats spellings as equal: `allowedVlans` as a set (`1-3` equals
  `1,2,3`, `1-4094` equals `all`), `tags` as a set, and `"10"` equal to `10`.
  `true` is not equal to `1`.
- **Firewall rules are an ordered list,** because an MX applies the first
  match. The diff uses difflib, so inserting one rule shows as one addition.
  Comments are compared too: unlike the audit, a plan describes configuration,
  and a comment is configuration.
- **Missing defaults:** a rule that omits `srcPort`, `destPort`, `comment` or
  `syslogEnabled` is compared as `Any`, `Any`, empty and `false`.

## Why there is no `apply`

A tool that can change a production network should only exist once the plan
it acts on is trustworthy, and once its guardrails are obvious enough that a
reviewer can see them without reading the code. Neither is true of a v0.2.
Concretely, `apply` would need at least:

1. **Plan files.** Apply exactly the reviewed plan, refuse if live state has
   changed since it was computed. Otherwise "apply" means "apply whatever
   the diff is now", which is not what was approved.
2. **Ordering.** Some changes have dependencies: a VLAN must exist on the MX
   before a trunk can carry it; a firewall rule referencing `VLAN(50).*`
   needs VLAN 50. The plan currently lists changes; it doesn't order them.
3. **Blast-radius limits.** Refuse plans that touch uplinks and firewall
   rules in the same run, or more than N ports, without an explicit flag.
4. **A separate, write-capable client,** outside `src/`, so the read-only CI
   guarantee for the audit and the plan stays true.

Until then, the plan is the deliverable: an exact, reviewable list of
changes for a human to make through the normal change process, and a way to
prove afterwards that they were made.

## Known limitations

- `export` and `plan` share the audit's API client and have run against the
  demo fixtures and mocked responses; they haven't had their own live run.
- Switch stacks, port channels and per-port schedules aren't modelled.
- Networks are matched by name. Renaming a network in Dashboard makes the
  intent refer to a network that no longer exists, which the plan reports as
  an error.
