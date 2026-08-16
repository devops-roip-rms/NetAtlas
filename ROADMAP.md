# NetAtlas development ideas

## Highest value next

1. **Credential profiles through Docker secrets** — multiple SSH and Windows credential sets, selected per site/VLAN, with secrets mounted at runtime instead of saved in inventory.
2. **Agentless Windows WinRM from Linux** — NTLM/Kerberos support in the container for RDP-only servers, giving exact Windows edition, hostname, CPU, RAM, and disk even when SSH is disabled.
3. **Scheduled scans and change detection** — compare each run with the previous one and highlight new hosts, disappeared hosts, service changes, OS upgrades, and resource drift.
4. **Per-host rescan and correction** — retry one endpoint, override an incorrect OS classification, and preserve administrator notes without rescanning every VLAN.

## Inventory depth

5. **SNMP enrichment** — model, serial number, interface inventory, switch port, uptime, and firmware for network devices.
6. **MAC address and vendor discovery** — use ARP/neighbor data through a small probe at each site, because a central routed scanner cannot see remote-layer-2 MAC addresses.
7. **Directory and DNS integration** — correlate results with Active Directory and DNS records to find stale records and unmanaged servers.
8. **Application fingerprints** — capture TLS certificate names/expiry, web server product, SSH host-key fingerprint, and RDP certificate identity.

## Operations and governance

9. **Topology view** — site → VLAN → OS → endpoint map with filters and service health indicators.
10. **Role-based access and audit log** — useful if the appliance becomes shared by multiple administrators.
11. **Additional exports** — Ansible inventory, CSV/Excel, mRemoteNG, Royal TS, and CMDB/API synchronization.
12. **Signed offline releases** — sign the OCI image and software bill of materials on the connected build station, then verify both inside the air gap.
