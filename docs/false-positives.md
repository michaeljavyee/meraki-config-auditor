# Where this tool is wrong

Every check here is a comparison between live configuration and a declared
baseline, plus a few structural inferences. The inferences are where it can be
wrong. This page lists the known ways, so a finding can be challenged on
specifics rather than dismissed wholesale.

## VLAN / trunk check

**Uplinks are identified by tag or name, not by topology.** A trunk is an
uplink if it is tagged `uplink` (or a tag listed in `trunks.uplink_port_tags`)
or its name contains `uplink`. Consequences:

- *False negative:* an uplink named `Po1` or `to-core` with no tag is not
  assessed. The tool records this as a scope limitation when it sees trunks on
  a switch but cannot identify the uplink. Fix: tag uplinks in Dashboard.
- *False positive:* a downlink port named "uplink to IDF2" will be assessed as
  if it were this switch's uplink, and will be expected to carry every VLAN in
  use on this switch. Usually still correct (a downlink normally carries those
  VLANs too), but not always.

**"In use" means "assigned to an enabled access port."** A port can be
assigned to VLAN 40 with nothing plugged into it. The CRITICAL finding says
those ports have no path off the switch, which is true; it does not prove a
device is currently connected and failing. Port status (`/devices/{serial}/
switch/ports/statuses`) would close this gap and is a planned refinement.

**Switches with local L3 interfaces.** If a switch routes a VLAN itself (an
MS layer-3 interface), that VLAN doesn't need to be on the uplink trunk. The
check doesn't yet read switch L3 interfaces, so it will report such a VLAN as
cut off. If you route on your access switches, expect this one.

**Native VLAN comparison depends on link-layer topology.** Link pairs come
from `/networks/{id}/topology/linkLayer`. If LLDP/CDP is off, a neighbour is
non-Meraki, or the reported port ID can't be mapped to a port number (port
IDs are normalised from forms like `8`, `Port 8` and `GigabitEthernet1/0/8`),
the link is skipped silently rather than guessed. The response shape was built
from the Dashboard API documentation and the demo fixtures; it has not yet
been verified against a live organization.

**Stacks and port channels** are not modelled. A link aggregate appears as
its member ports, each of which must individually be tagged as an uplink.

## Firewall check

**Shadowing is structural, not semantic.** An earlier rule shadows a later
one when every field covers it: `Any` covers everything, a CIDR covers its
subnets, and everything else must match exactly. So:

- `VLAN(30).*` and `10.30.30.0/24` may be the same subnet at a given site,
  but are not treated as overlapping. Real shadowing expressed through
  different notations is missed (false negative).
- Port ranges (`8000-8100`) are compared by exact string, not by range.

**Rule identity ignores comments.** A rule with the same behaviour but a
different comment is a match. That's deliberate, but it means two different
intentions written as the same rule are indistinguishable.

**Only outbound L3 rules are read.** Inbound rules, port forwarding, 1:1 NAT,
L7 rules and group-policy firewall rules are out of scope, so an exposure
created through any of those is not reported.

## SSID check

**Only fields listed in the baseline are compared.** If the baseline doesn't
mention `splashPage`, a captive-portal difference between sites is invisible.
That is the intended behaviour - the baseline decides what consistency means
- but a thin baseline produces a clean report.

**SSIDs are matched by name.** Two SSIDs with the same name in different SSID
slots are matched correctly; a renamed SSID appears as one missing standard
SSID plus one unknown SSID.

## Firmware check

**Versions are compared numerically from the firmware string.**
`switch-17-1-4` becomes `(17, 1, 4)`. Builds that carry a suffix
(`wireless-31-1-beta2`) are compared on their numeric parts only, so two
different betas of the same number compare equal.

**"Ahead of baseline" is reported LOW, not ignored.** A deliberate pilot
will be flagged. Record pilots in the baseline to silence them.

## General

**A clean report means "matches the baseline", not "is secure".** The tool
measures drift. A network that faithfully implements a weak standard will
report no findings.
