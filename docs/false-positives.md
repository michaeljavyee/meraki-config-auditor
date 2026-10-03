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

## IPAM check

**Utilisation is measured from clients seen over 7 days, not live leases.**
Every distinct address used by any client in the window counts, so a guest
network with heavy churn and a one-day lease reads higher than its real
concurrent use. The number errs high on purpose: a pool that looks 90% used
over a week is one bad lunchtime away from 100%. Shorter windows are a
one-line change (`CLIENT_WINDOW_DAYS` in `src/checks/base.py`).

**"Not seen" isn't "gone".** A reservation is flagged LOW when its device
hasn't appeared in the window. A device that's only powered on monthly (a
backup NAS, a DR server) will be flagged. So will devices on a VLAN that is
currently cut off, such as the cameras behind a trunk the VLAN/trunk check
flags as CRITICAL; fix connectivity first, then re-run.

**Relayed DHCP isn't assessed.** When a VLAN relays DHCP to another server
(or doesn't serve DHCP at all), the pool lives outside Dashboard. The report
says so as a scope limitation rather than computing a meaningless number.

**Cross-site overlap is reported even if the sites will never connect.**
Overlap between networks is MEDIUM because it's harmless until a VPN joins
them. If two networks are permanently isolated by design, the finding is
noise for that pair.

**Clients outside every subnet** are often a rogue DHCP server, but can also be
a device with a stale static configuration, or a client behind a NAT device
that Dashboard sees through. The finding names the MAC so the port can be
traced; it doesn't claim which cause it is.

**IPv6 and DNS are out of scope.** Only IPv4 subnets, pools and reservations
are reconciled.

## 802.1X / NAC check

**Outcomes are inferred from Dashboard's client record, not from RADIUS.** A
wired client on an enforcing port with an 802.1X identity in `user` counts as
802.1X; with no identity, as MAB; in the policy's guest or failed-auth VLAN,
as failed. If RADIUS assigns VLANs dynamically, a legitimately authenticated
client can sit in a VLAN the check reads as the failed-auth VLAN. The fields
used (`user`, `switchport`, `recentDeviceSerial`, `os`) come from the
documented clients endpoint and haven't been checked against a live org yet.

**"General-purpose computer" comes from Dashboard's OS fingerprint.** A
laptop reported with no OS isn't flagged when it uses MAB; a thin client
fingerprinted as Linux is. The finding names the MAC and OS so either is easy
to check.

**Exemptions are by tag.** A camera port that isn't tagged `camera` (or another
tag in `nac.exempt_port_tags`) counts as a coverage gap. That's deliberate:
an exemption nobody wrote down looks exactly like a port nobody configured.

**Fail-open is reported, not judged.** Critical-auth into a data VLAN is
MEDIUM because it is often the right call for availability. The finding asks
for it to be a recorded decision with RADIUS monitoring, not for it to be
removed.

**Wireless 802.1X isn't covered here.** SSID authentication mode is checked by
the SSID check; RADIUS behaviour on wireless isn't assessed.

## General

**A clean report means "matches the baseline", not "is secure".** The tool
measures drift. A network that faithfully implements a weak standard will
report no findings.
