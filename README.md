# NetAtlas

NetAtlas is a local multi-site IPv4 inventory scanner with a browser GUI. It checks SSH, RDP, HTTP, and HTTPS, resolves hostnames, fingerprints operating systems, can optionally collect hardware facts, and exports a MobaXterm session library grouped by site and VLAN.

## Start

1. Install Python 3.10 or newer if it is not already installed.
2. Double-click `start.cmd`. Alternatively, run `powershell -ExecutionPolicy Bypass -File .\start.ps1`.
3. NetAtlas opens at `http://127.0.0.1:8765`.

The basic scanner uses the Python standard library. For password-authenticated SSH enrichment when running directly on Windows, install `requirements.txt`; the Docker image already includes it. Scan history is stored locally under `data/`.

## Docker and air-gap deployment

The image includes Python, Nmap, OpenSSH, and the complete GUI. Build a transferable image and checksum with:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-offline.ps1
```

See `AIRGAP.md` for loading, persistent storage, credential handling, and network routing notes. Runtime operation has no internet dependencies.

Docker deployments listen on all node interfaces by default. Restrict TCP/8765 to the management subnet or use an HTTPS reverse proxy because scan credentials are entered through the web interface.

## Accuracy and access

- A host is listed only when TCP 22, 80, 443, or 3389 accepts a connection.
- Lightweight OS labels are evidence-based but not definitive. Install Nmap and enable deep inspection for better service and OS versions.
- SSH resource collection supports separate username/password profiles for Linux and Windows OpenSSH. Passwords are memory-only and cleared after the scan; they are never saved or exported.
- Windows resource collection uses PowerShell remoting (WinRM) with the Windows identity running NetAtlas. The target must allow WinRM and authorize that identity.
- Services are independent: a Windows server listening on both SSH and RDP is listed with both protocols and receives both MobaXterm sessions.
- Scanning uses only the networks you enter. Only scan networks you own or are authorized to assess.

## MobaXterm export

After a completed scan, choose **Export MobaXterm**. Windows hosts are grouped beneath `Windows` and receive SSH and RDP entries. Linux hosts are grouped beneath `Linux` and receive SSH only. Site and VLAN folders are retained under each OS block. HTTP and HTTPS remain inventory-only and are never exported as sessions. Passwords are never exported. A generic CSV is also available as a compatibility fallback.

In MobaXterm, right-click **User sessions** and choose **Import sessions from file**.
