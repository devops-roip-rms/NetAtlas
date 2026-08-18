# NetAtlas

NetAtlas is a local multi-site IPv4 inventory scanner with a browser GUI. It checks SSH, RDP, HTTP, and HTTPS, resolves hostnames, fingerprints operating systems, can optionally collect hardware facts, and exports a MobaXterm session library grouped by site and VLAN.

## Start

1. Install Python 3.10 or newer if it is not already installed.
2. Double-click `start.cmd`. Alternatively, run `powershell -ExecutionPolicy Bypass -File .\start.ps1`.
3. NetAtlas opens at `http://127.0.0.1:8765`.

The basic scanner uses the Python standard library. For password-authenticated SSH enrichment when running directly on Windows, install `requirements.txt`; the Docker image already includes it. Scan history and the SQLite remembered-host inventory are stored locally under `data/`.

The Hosts and Remembered Hosts tables support per-column filters and click-to-sort headers. Select the required rows in **Hosts** before downloading inventory CSV, compatibility CSV, or MobaXterm sessions; exports contain only the selected hosts. Remembered hosts can be removed with an explicit confirmation prompt.

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
- SSH resource collection supports separate username/password profiles for Linux and Windows OpenSSH. Passwords are memory-only and cleared after the scan; they are never saved or exported.
- NetAtlas tries both standard password authentication and password-backed keyboard-interactive authentication. A transient connection or negotiation failure receives one fresh retry; rejected credentials are not repeatedly retried. SSH enrichment is capped at four concurrent hosts to avoid bursts against the network and servers. Host details and inventory CSV distinguish rejected credentials, negotiation errors, timeouts, and a successful login whose inventory commands were restricted.
- Windows resource collection uses PowerShell remoting (WinRM) with the Windows identity running NetAtlas. The target must allow WinRM and authorize that identity.
- Services are independent: a Windows server listening on both SSH and RDP is listed with both protocols and receives both MobaXterm sessions.
- NetAtlas infers a role name from the hostname, operating system, and verified services. Role names can be edited in **Remembered Hosts** and manual values survive later scans.
- Only resolved hostnames are added to **Remembered Hosts**. Repeat scans update the existing site/IP record and add newly resolved hosts.
- The **Direct server targets** field accepts individual IPv4 addresses with an optional label. Enable **Direct servers only** to run those IPs without either VLAN list, or leave it off to combine direct targets with the VLAN scan.
- The internal DNS suffix `.tng.topsecret` is removed from displayed, remembered, CSV, and MobaXterm hostnames.
- Scanning uses only the networks you enter. Only scan networks you own or are authorized to assess.

## MobaXterm export

After a completed scan, filter or sort the inventory, select the required hosts, and choose **Export selected**. Windows hosts are grouped beneath `Windows` and receive SSH and RDP entries. Linux hosts are grouped beneath `Linux` and receive SSH only. Site and VLAN folders are retained under each OS block. HTTP and HTTPS remain inventory-only and are never exported as sessions. Passwords are never exported. A selected-host inventory CSV and generic compatibility CSV are also available.

Every host with a verified SSH service has a **PuTTY** action in Hosts, Remembered Hosts, and host details. In host details, download **Set up PuTTY links** and run `register-putty-handler.ps1` once on the Windows browser workstation. NetAtlas then opens `putty.exe -ssh "username@ip" -P 22`; it also copies that command on every click as a fallback. The username is included when known. Passwords are intentionally excluded because credentials in URLs or process arguments can leak.

The bulk MobaXterm export is unchanged. In MobaXterm, right-click **User sessions** and choose **Import sessions from file**.
