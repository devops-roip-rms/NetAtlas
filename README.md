# NetAtlas

NetAtlas is a local multi-site IPv4 inventory scanner with a browser GUI. It checks SSH, RDP, HTTP, and HTTPS, resolves hostnames, fingerprints operating systems, collects hardware facts, and exports an ordered MobaXterm session library grouped into your own systems.

## Start

1. Install Python 3.10 or newer if it is not already installed.
2. Double-click `start.cmd`. Alternatively, run `powershell -ExecutionPolicy Bypass -File .\start.ps1`.
3. NetAtlas opens at `http://127.0.0.1:8765`.

The basic scanner uses the Python standard library. For password-authenticated SSH enrichment when running directly on Windows, install `requirements.txt`; the Docker image already includes it. Scan history and the SQLite remembered-host inventory are stored locally under `data/`.

The Hosts and Remembered Hosts tables support per-column filters, click-to-sort headers, and selected-only exports. Both views can generate compatibility CSV and MobaXterm session lists; the live Hosts view also exports the full inventory CSV. Remembered hosts can be removed with an explicit confirmation prompt.

In 1.2.11, **Delete selected** removes the entire selected remembered set, including selections hidden by filters. The confirmation shows endpoints and warns that deletion cannot be undone; later scans may add them again. Cancelling does not change inventory.

## Docker and air-gap deployment

The image includes Python, Nmap, OpenSSH, and the complete GUI. Build a transferable image and checksum with:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-offline.ps1
```

See `AIRGAP.md` for loading, persistent storage, credential handling, and network routing notes. Runtime operation has no internet dependencies.

Before the first Linux air-gap run, prepare the local database folder from the directory that contains the loader and image archive:

```sh
mkdir -p ./netatlas-data
sudo chown -R 10001:10001 ./netatlas-data
sudo chmod 750 ./netatlas-data
```

On an SELinux-enforcing host such as RHEL, also run `sudo chcon -Rt container_file_t ./netatlas-data`. The Linux loader repeats the ownership correction and mounts the folder with the SELinux private-container label. Keep this folder when replacing the container because it contains `hosts.db` and scan history.

Docker deployments listen on all node interfaces by default. Restrict TCP/8765 to the management subnet or use an HTTPS reverse proxy because scan credentials are entered through the web interface.

## Accuracy and access

- A host is listed only when TCP 22, 80, 443, or 3389 accepts a connection.
- Lightweight service, RDP, and reverse-DNS discovery is the default. Deep Nmap inspection is opt-in and can provide better service and OS versions at the cost of extra time and target load.
- SSH resource collection supports separate username/password profiles for Linux and Windows OpenSSH. Manual scan passwords are memory-only and cleared after the scan. Scheduled passwords are encrypted locally for restart recovery; passwords never appear in API responses, history or exports.
- NetAtlas tries both standard password authentication and password-backed keyboard-interactive authentication. A transient connection or negotiation failure receives one fresh retry; rejected credentials are not repeatedly retried. SSH enrichment is capped at four concurrent hosts to avoid bursts against the network and servers. Host details and inventory CSV distinguish rejected credentials, negotiation errors, timeouts, and a successful login whose inventory commands were restricted.
- Windows resource collection uses PowerShell remoting (WinRM) with the Windows identity running NetAtlas. The target must allow WinRM and authorize that identity.
- Services are independent: a Windows server listening on both SSH and RDP is listed with both protocols and receives both MobaXterm sessions.
- The default role is the resolved hostname. Role names can be edited in **Remembered Hosts** and manual values survive later scans.
- Only resolved hostnames are added to **Remembered Hosts**. Manual scans update the existing site/IP record and add newly resolved hosts. Background scans update existing records and send new hosts to the review queue.
- The **Direct server targets / scopes** field accepts individual IPv4 addresses or CIDR scopes (/20–/32) with an optional label, one per line (for example `Application network, 192.0.2.0/24`). Set the direct target site to scan a new site without assigning any VLAN. Enable **Direct servers only** to run these targets without either VLAN list, or leave it off to combine them. A direct server's site can be changed in **Remembered Hosts**, and that manual site survives later scans. Background scans support the same scopes.
- The internal DNS suffix `.tng.topsecret` is removed from displayed, remembered, CSV, and MobaXterm hostnames.
- Scanning uses only the networks you enter. Only scan networks you own or are authorized to assess.

## MobaXterm export

From **Hosts**, **Remembered Hosts**, or **Systems**, select the required hosts and choose **Export selected**. Remembered exports use your named systems and the parent-folder rules below; hosts without a system use `Unassigned`. Systems use name order and servers retain their saved order within a system. Current-scan exports use site/VLAN folders, or just the site for direct scopes. There are no intermediate OS folders. Windows receives SSH and RDP entries; Linux receives SSH only. MobaXterm names use the role (hostname fallback), without protocol suffixes. Duplicate names, including a Windows server's second session, receive `(2)`, `(3)`, etc. to avoid overwriting INI keys. The session icon identifies its protocol. CSV exports include `role` and `system` columns. HTTP and HTTPS remain inventory-only. Passwords are never exported. In MobaXterm, right-click **User sessions** and choose **Import sessions from file**.

In 1.2.10, system names matching `digits-digits` (for example `99-3`, `88-1`, `392-3`, `874-3`) are grouped under `RAFAEL`. When two or more catalog system names share a hyphen prefix, it becomes a parent folder; additional shared prefixes become environment parents. Full system names remain leaf folders. For example:

```text
RMS
├── RMS-A
├── RMS-B
└── NP
    ├── RMS-NP-A
    └── RMS-NP-B
RAFAEL
├── 99-3
└── 392-3
```

Paths use the entire catalog, including empty systems, so selected-only exports keep the same hierarchy. Single unshared names and `Unassigned` remain at the top level. Systems are sorted by name, case-insensitively with numeric ordering (`RMS-2` before `RMS-10`); saved host order within each system is preserved. Compatibility and inventory CSV exports contain both `role` and `system` columns. CSV `system` is the original full name, while `folder` is the grouped export path.

From 1.2.11, name order is the default until you drag system cards into your preferred order. Drag a card's header grip onto another card to place it before that system; drop onto Unassigned to put it last. The saved system order applies to the board, destination lists and exports, and survives restart. The **All systems** dropdown lets you show one or several systems using checkboxes; clear them or choose **Show all systems** to remove the filter. Hidden systems keep their relative order during rearrangement. **Select visible** selects hosts only from displayed systems. Existing hidden host selections remain selected until cleared.

In each MobaXterm export, every root group receives a randomly selected built-in icon; its descendants all inherit that icon. Session SSH/RDP icons are unchanged. Icons are chosen per export and may differ next time.

## Remembered Overview and Systems

Overview reads only the durable inventory, independently of the selected scan. It shows total remembered hosts, reachable/unreachable/unchecked hosts, services on hosts reachable at their last check, OS composition and exact OS counts, saved resource totals per site, counts per site/VLAN, and the ten most recently added hosts with dates. Reachability means TCP service response at the last completed check, not a continuous health check. Older records are initially unchecked. A complete error-free scan updates only addresses in its own site/scope; an offline host stays remembered. Resource totals retain the last collected facts. Identical VLAN names at different sites stay separate.

Create a system in **Systems**, select servers and drag them together into its card. Drop above a server to insert there; dropping into empty card space appends. Use the arrows to order servers within a system, or **Move selected** as an alternative to dragging. System cards and destination lists are always sorted by name. Clicking a selected host's **Move…** action moves the entire selection; clicking an unselected host moves only that host. Rename a system without losing membership. Deleting a system moves its servers to Unassigned without deleting them. Roles, site overrides, membership and host ordering survive rescans. Remembered Hosts includes a searchable, sortable System column, showing Unassigned when there is no system.

Selection clears after a successful drop or manual move. Hold a dragged server near the top or bottom of the viewport to scroll. Each server also has a **Move…** action with a destination-system dialog, available from remembered host details as well. Click Overview metrics, OS groups, or site/VLAN groups to open the corresponding filtered remembered list; **Show all remembered hosts** clears that group filter.

Use the red flag beside a remembered host or in its details to mark it as a deletion candidate. The **Red flags** tab lists these hosts and shows the total in its badge. Flags persist across scans and can be cleared; marking a host does not delete it. Actual removal still requires confirmation.

## Background scans and review

In **Background scans**, enter an interval (1–10080 minutes), the two site names and VLAN lists, and optional separate Linux/Windows SSH credentials. **Copy current scan setup** copies the manual VLAN and SSH profile inputs. Save to start the first run as soon as the scanner is free. Subsequent runs begin one interval after the previous run finishes. Manual and scheduled scans never overlap. Scheduling continues with the browser closed while NetAtlas runs, and resumes when the container restarts.

SSH profiles have **Show/Hide** password controls. Recent scans includes both manual and background runs with explicit labels. Progress stays at most 99% while enrichment and inventory updates are running, and reaches 100% only when the scan completes.

Background scans refresh remembered hosts but place newly resolved site/IP records in **New hosts**. The tab count shows how many await review. Select records to add them to Remembered, or dismiss them so later background sightings stay hidden. Repeated discoveries update one record. Manual scans retain their automatic-add behavior. Unresolved new hostnames do not enter the queue.

## Duplicate IPs for one server

Remembered inventory matches normalized, case-insensitive hostnames within the same site. If the same hostname responds on two addresses, prefer the IP whose last octet does not end in `0`: `.13` over `.10`, `.52` over `.50`, `.107` over `.100`. If both have the same preference, retain the oldest saved record (numeric address breaks ties). If all alternatives end in `0`, retain one rather than dropping the server. Identical names in different sites stay separate. Unresolved hosts do not qualify for this rule, and scan results still show all responding endpoints.

On a new scan, matching remembered duplicates are merged transactionally. Manual role, system membership, red flag and saved collected facts survive an address replacement; if conflicting manual values exist, the preferred record's values win. Removed duplicate rows are retained as JSON snapshots in the local SQLite `duplicate_host_archive` table for administrator recovery. Back up `netatlas-data` before upgrading. Background aliases of an already-known server update that server; new multi-address identities show one review entry, and approving/dismissing applies to the server identity.

The SQLite database saves the schedule, systems, discovery queue and inventory. Scheduled credentials use Fernet authenticated encryption; `schedule.key` in the same local data volume is created with mode 0600 on Linux. Back up the entire `netatlas-data` folder, including this key, to preserve schedule credentials. Protect that folder: a user who can read both the database and key can decrypt them. Re-enter passwords when replacing a schedule; **Stop schedule** cancels its active run and clears saved credentials. No schedule passwords are returned to the GUI, history or exports.
