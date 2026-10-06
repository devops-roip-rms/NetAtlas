# NetAtlas

NetAtlas is a local multi-site IPv4 inventory scanner with a browser GUI. It checks SSH, RDP, HTTP, and HTTPS, resolves hostnames, fingerprints operating systems, collects hardware facts, and exports an ordered MobaXterm session library grouped into your own systems.

## Start

1. Install Python 3.10 or newer if it is not already installed.
2. Double-click `start.cmd`. Alternatively, run `powershell -ExecutionPolicy Bypass -File .\start.ps1`.
3. NetAtlas opens at `http://127.0.0.1:8765`.

The basic scanner uses the Python standard library. For password-authenticated SSH enrichment when running directly on Windows, install `requirements.txt`; the Docker image already includes it. Scan history and the SQLite remembered-host inventory are stored locally under `data/`.

The Hosts and Remembered Hosts tables support per-column filters, click-to-sort headers, and selected-only exports. Both views can generate compatibility CSV and MobaXterm session lists; the live Hosts view also exports the full inventory CSV. Remembered hosts can be removed with an explicit confirmation prompt.

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
- The **Direct server targets** field accepts individual IPv4 addresses with an optional label. Enable **Direct servers only** to run those IPs without either VLAN list, or leave it off to combine direct targets with the VLAN scan. A direct server's site can be changed in **Remembered Hosts**, and that manual site survives later scans.
- The internal DNS suffix `.tng.topsecret` is removed from displayed, remembered, CSV, and MobaXterm hostnames.
- Scanning uses only the networks you enter. Only scan networks you own or are authorized to assess.

## MobaXterm export

From **Hosts**, **Remembered Hosts**, or **Systems**, select the required hosts and choose **Export selected**. Remembered exports use folders such as `RMS-Site-A\Windows` and `RMS-Site-A\Linux`; hosts without a system use `Unassigned`. System and server order are saved and used in MobaXterm and compatibility CSV exports. Current-scan exports keep the OS/site/VLAN hierarchy. Windows receives SSH and RDP entries; Linux receives SSH only. HTTP and HTTPS remain inventory-only. Passwords are never exported. In MobaXterm, right-click **User sessions** and choose **Import sessions from file**.

## Remembered Overview and Systems

Overview reads only the durable inventory, independently of the selected scan. It shows total remembered hosts, reachable/unreachable/unchecked hosts, services on hosts reachable at their last check, OS composition and exact OS counts, saved resource totals per site, counts per site/VLAN, and the ten most recently added hosts with dates. Reachability means TCP service response at the last completed check, not a continuous health check. Older records are initially unchecked. A complete error-free scan updates only addresses in its own site/scope; an offline host stays remembered. Resource totals retain the last collected facts. Identical VLAN names at different sites stay separate.

Create a system in **Systems**, select servers and drag them together into its card. Drop above a server to insert there; dropping into empty card space appends. Use the arrows to order servers and systems, or **Move selected** as an alternative to dragging. Rename a system without losing membership. Deleting a system moves its servers to Unassigned without deleting them. Roles, site overrides, membership and ordering survive rescans.

## Background scans and review

In **Background scans**, enter an interval (1–10080 minutes), the two site names and VLAN lists, and optional separate Linux/Windows SSH credentials. **Copy current scan setup** copies the manual VLAN and SSH profile inputs. Save to start the first run as soon as the scanner is free. Subsequent runs begin one interval after the previous run finishes. Manual and scheduled scans never overlap. Scheduling continues with the browser closed while NetAtlas runs, and resumes when the container restarts.

Background scans refresh remembered hosts but place newly resolved site/IP records in **New hosts**. The tab count shows how many await review. Select records to add them to Remembered, or dismiss them so later background sightings stay hidden. Repeated discoveries update one record. Manual scans retain their automatic-add behavior. Unresolved new hostnames do not enter the queue.

The SQLite database saves the schedule, systems, discovery queue and inventory. Scheduled credentials use Fernet authenticated encryption; `schedule.key` in the same local data volume is created with mode 0600 on Linux. Back up the entire `netatlas-data` folder, including this key, to preserve schedule credentials. Protect that folder: a user who can read both the database and key can decrypt them. Re-enter passwords when replacing a schedule; **Stop schedule** cancels its active run and clears saved credentials. No schedule passwords are returned to the GUI, history or exports.
