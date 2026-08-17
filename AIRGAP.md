# NetAtlas air-gap deployment

The running container makes no internet or cloud requests. All fonts, styles, scripts, scanning logic, Nmap, and OpenSSH tools are inside the image.

## 1. Build on a connected workstation

From the NetAtlas folder on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-offline.ps1
```

For an ARM64 Docker host, add `-Platform linux/arm64`.

The script creates `dist/netatlas-1.2.3-linux-amd64.tar`, its SHA-256 checksum, and the offline loader scripts. Copy the entire `dist` folder to approved removable media.

## 2. Load and run inside the air gap

Windows Docker host:

```powershell
.\load-and-run-airgap.ps1 -Archive .\netatlas-1.2.3-linux-amd64.tar
```

Linux Docker host:

```sh
sh ./load-and-run-airgap.sh ./netatlas-1.2.3-linux-amd64.tar
```

The Linux loader accepts checksum files copied from either Windows or Linux and verifies the hash independently of line-ending format.

Open `http://<NETATLAS-NODE-IP>:8765`. The loader publishes on all node interfaces by default. Scan history is kept outside the container in `netatlas-data`, so replacing the image does not erase inventory.

## SSH credentials

The scan setup provides independent Linux SSH and Windows OpenSSH profiles. Configure either or both username/password pairs. NetAtlas tries the OS-matched profile first and, for initially unknown hosts, safely falls back to the other configured profile. Passwords are held only in server memory while authenticated enrichment runs, then discarded. They are excluded from saved scan history, API responses, CSV, and MobaXterm exports.

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

Deep Nmap OS detection uses `NET_RAW` and `NET_ADMIN`; the loader grants only those capabilities. The application itself runs as a non-root user with a read-only container filesystem.

HTTP and HTTPS remain visible in inventory but are not exported as MobaXterm sessions. Windows hosts are exported beneath a `Windows` tree with both SSH and RDP sessions. Linux hosts are exported beneath a `Linux` tree with SSH only.
