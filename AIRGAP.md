# NetAtlas air-gap deployment

The running container makes no internet or cloud requests. All fonts, styles, scripts, scanning logic, Nmap, and OpenSSH tools are inside the image.

## 1. Build on a connected workstation

From the NetAtlas folder on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-offline.ps1
```

For an ARM64 Docker host, add `-Platform linux/arm64`.

The script creates `dist/netatlas-1.2.10-linux-amd64.tar`, its SHA-256 checksum, and the offline loader scripts. Copy the entire `dist` folder to approved removable media.

## 2. Load and run inside the air gap

Windows Docker host:

```powershell
New-Item -ItemType Directory -Force .\netatlas-data
.\load-and-run-airgap.ps1 -Archive .\netatlas-1.2.10-linux-amd64.tar -DataPath .\netatlas-data
```

Linux Docker host—first create the persistent local database folder:

```sh
mkdir -p ./netatlas-data
sudo chown -R 10001:10001 ./netatlas-data
sudo chmod 750 ./netatlas-data
```

On RHEL or another SELinux-enforcing host, label it for container access:

```sh
sudo chcon -Rt container_file_t ./netatlas-data
```

Then load and run NetAtlas:

```sh
sh ./load-and-run-airgap.sh ./netatlas-1.2.10-linux-amd64.tar 8765 ./netatlas-data 0.0.0.0
```

The Linux loader accepts checksum files copied from either Windows or Linux and verifies the hash independently of line-ending format. It also normalizes the local folder ownership to the container user (UID/GID 10001) and applies Docker's private SELinux label during the mount.

Shell scripts are distributed with Linux LF line endings. If an editor changes them and `sh` reports `set: invalid option`, repair the loader with `sed -i 's/\r$//' ./load-and-run-airgap.sh`. Always use the loader from the same version as the image archive.

Open `http://<NETATLAS-NODE-IP>:8765`. The loader publishes on all node interfaces by default. `netatlas-data/hosts.db` and scan history stay outside the container, so replacing the image does not erase inventory. Do not delete this folder unless you intentionally want to reset NetAtlas.

## SSH credentials

The scan setup provides independent Linux SSH and Windows OpenSSH profiles. Configure either or both username/password pairs. NetAtlas tries the OS-matched profile first and, for initially unknown hosts, falls back to the other configured profile. It supports standard password and password-backed keyboard-interactive login. Transient connection or negotiation failures receive one fresh retry; rejected credentials do not. Enrichment uses at most four concurrent SSH connections. Manual scan passwords are held in memory during enrichment, then discarded. Background schedule passwords are encrypted locally to support restarts. All passwords are excluded from saved scan history, API responses, CSV, and MobaXterm exports.

If manual SSH works but enrichment does not, open the host details or selected inventory CSV and check the SSH diagnostic fields. Common cases are a true MFA/OTP prompt, a restricted shell or disabled command execution, an account policy such as `AllowUsers`, a timeout, or algorithms that the bundled SSH client and server cannot negotiate. A successful login with unavailable PowerShell, CIM, `/etc/os-release`, `df`, or `sudo` commands is reported separately from bad credentials.

Because the SSH credential form is sensitive, allow port 8765 only from your management subnet. For production remote access, place NetAtlas behind an approved HTTPS reverse proxy. To restrict access to the node itself, pass `-BindAddress 127.0.0.1` on Windows or use `127.0.0.1` as the fourth Linux loader argument.

If remote clients still cannot connect, confirm the container is listening with `docker ps` and `ss -lntp | grep 8765`, then allow TCP/8765 through the node firewall only from the management subnet.

The original 1.1 Linux loader printed a localhost URL, but its Docker argument was `-p 8765:8765`, which actually published on every host interface. Use these checks to diagnose the effective 1.2 runtime rather than relying on the printed URL:

```sh
docker ps --filter name=netatlas --format 'status={{.Status}} ports={{.Ports}}'
docker inspect netatlas --format '{{json .HostConfig.PortBindings}}'
docker logs --tail 50 netatlas
curl -v http://127.0.0.1:8765/api/health
```

The port listing should contain `0.0.0.0:8765->8765/tcp`. If localhost works but the node IP does not, the remaining block is the host firewall or an upstream ACL. If localhost fails, inspect the container logs and health status.

Authenticated SSH reads the system hostname, exact OS release, logical CPU count, physical memory, and system-disk capacity. Linux uses `/etc/os-release`; Windows OpenSSH uses PowerShell and CIM. The MobaXterm export dialog also accepts separate Linux SSH, Windows SSH, and Windows RDP usernames.

## Network routing

The container must have routes to both sites and all VLANs. Docker Desktop normally sends outbound scans through the host, but VPN clients and restrictive host firewalls may block private routes. On a Linux Docker host, host networking is an alternative when bridge/NAT routing cannot reach the VLANs.

Deep Nmap OS detection is off by default. Enable it only when the extra fingerprint detail is needed; it uses at most two workers and requires `NET_RAW` and `NET_ADMIN`. The loader grants only those capabilities. The application itself runs as a non-root user with a read-only container filesystem.

HTTP and HTTPS remain visible in inventory but are not exported as MobaXterm sessions. Filter or sort any column, select the required hosts, and export only that selection. Current-scan exports group by site/VLAN; direct scopes have no VLAN. Remembered and Systems exports sort systems by name and preserve host order, using the parent-folder rules below without Windows/Linux subfolders. MobaXterm session names use roles without protocol suffixes; duplicate names receive numeric suffixes so both Windows SSH and RDP entries remain importable. Linux receives SSH only. CSV exports include role and system.

Version 1.2.10 migrates the existing database automatically. Keep and back up your existing `netatlas-data` folder when upgrading; do not replace it with an empty folder. Direct targets accept CIDR scopes (/20–/32) with a new site and no VLAN. Red flags, system membership, manual roles and site overrides persist across rescans. Red flags only mark deletion candidates; removal still requires confirmation.

For a small ad-hoc scan, enter the individual IPs under **Direct server targets** and enable **Direct servers only**. The populated Site A and Site B VLAN lists are ignored for that run.

Remembered Hosts can export selected rows to MobaXterm or compatibility CSV without rerunning a scan. Direct `/32` targets also expose an editable site field; the SQLite migration adds a lock flag automatically so that assignment survives future scans.

## Background scans, systems and upgrades

Overview is entirely based on Remembered Hosts, including OS, resource and site/VLAN totals, latest additions and reachability from each host's last completed check. Run a manual scan to establish initial reachability for older inventory. A scan never marks another site's hosts offline, and cancelled/failed scans do not mark hosts offline.

Use **Systems** to create named groups (for example `RMS-Site-A`), select multiple servers, and drag them into a group. Drag above a host or use arrows to set host order. Clicking Move on a selected host moves the whole selection. Systems and destination lists are sorted by name; exports retain the saved host order inside each system. Remembered Hosts and CSV exports include System.

MobaXterm exports put numeric system names such as `99-3` under `RAFAEL`. Shared hyphenated prefixes form system/environment parents: `RMS-A/B` go under `RMS`, and `RMS-NP-A/B` go under `RMS\NP`. Full names remain leaf folders. Paths are determined from the full catalog, so selecting fewer hosts does not change the hierarchy. CSV retains the original system name in `system` and the grouped path in `folder`.

Configure **Background scans** with an interval, site/VLAN lists and credentials. Scheduling is handled by the container, so closing the browser does not stop it. New resolved hosts appear in **New hosts**, whose tab shows a pending count. Approve selected records to add them to Remembered, or dismiss them. Existing hosts are refreshed without changing their saved roles or system membership.

Keep the same `netatlas-data` mount during an upgrade. Database schema changes are automatic. It contains the saved schedule, inventory, systems, discovery queue and `schedule.key`, which encrypts scheduled credentials. Back up the entire folder and restrict access to it; possession of both the key and database allows decryption. Manual scan credentials remain memory-only. Stop the schedule to cancel its active scan and remove saved credentials; enter them again when replacing the schedule. The saved schedule resumes after restart and scans do not overlap.
