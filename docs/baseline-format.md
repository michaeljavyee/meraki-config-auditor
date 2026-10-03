# Baseline format

The baseline is a YAML file describing what correct configuration looks like.
Start from [`baselines/example.yaml`](../baselines/example.yaml). Every section
is optional; a check whose section is missing records that it was skipped as a
scope limitation in the report rather than silently passing.

```yaml
name: Acme network standard        # shown on the report cover
version: "2026.09"                 # quote it, or YAML may turn it into a number

scope:
  network_tags: [depot]            # audit only networks with any of these tags; [] = all

firmware:                          # target per Dashboard productType
  appliance: wired-18-2-11
  switch: switch-17-1-4
  wireless: wireless-30-7
  camera: camera-5-3

vlans:                             # ID -> role, used to label findings
  10: corp
  40: cameras

trunks:
  required_vlans: [1, 10, 20, 30, 40]   # must be allowed on every uplink trunk
  native_vlan: 1                         # expected native VLAN on uplinks
  uplink_port_tags: [uplink]             # a trunk with one of these tags is an uplink
  uplink_name_patterns: [uplink]         # ...or whose name contains one of these

nac:                              # 802.1X / NAC posture check
  required_on_access_ports: true   # enabled access ports must enforce an access policy
  exempt_port_tags: [uplink, camera, nac-exempt]   # ...unless tagged with one of these
  guest_vlan_roles: [guest]        # roles (from `vlans`) allowed as guest/failed-auth VLAN
  min_radius_servers: 2            # fewer is a single point of failure

firewall:
  l3_rules:                        # MX outbound rules, in order, without the default rule
    - comment: Guest cannot reach internal
      policy: deny                 # allow | deny
      protocol: any                # tcp | udp | icmp | icmp6 | any
      srcCidr: VLAN(30).*
      srcPort: Any                 # optional, defaults to Any
      destCidr: 10.0.0.0/8
      destPort: Any                # optional, defaults to Any

ssids:                             # matched to live SSIDs by name
  - name: Acme-Corp
    authMode: 8021x-radius         # any field from GET /networks/{id}/wireless/ssids
    wpaEncryptionMode: WPA2 only
    defaultVlanId: 10
```

## Notes

**Use `VLAN(n).*` in firewall rules.** It's Meraki's own syntax for "the
subnet of VLAN n on this appliance", so one rule describes every site even
when each site has its own address plan. The audit compares it by name, which
is what makes one baseline portable across sites.

**SSID fields use the API's names and values.** Copy them from a known-good
network: `GET /networks/{networkId}/wireless/ssids`. String comparison is
case-insensitive; booleans and numbers must match exactly.

**Firmware strings use Dashboard's format**, as returned in the `firmware`
field of `GET /organizations/{organizationId}/devices`.

**Keep the baseline in version control next to the reason it changed.** The
report prints the baseline's name, version and path, so a finding can always
be traced to the version of the standard it was measured against.
