# Changelog

## 1.2.2

- Added independent username/password profiles for Linux SSH and Windows OpenSSH.
- Added OS-aware credential selection with fallback for initially unknown hosts.
- Added separate Linux SSH and Windows SSH usernames to MobaXterm and compatibility CSV exports.
- Kept all SSH passwords memory-only and excluded them from API responses, history, and export files.

## 1.2.1

- Made the Docker host bind address configurable and defaulted air-gap deployments to `0.0.0.0` for remote management access.
- Added precise runtime diagnostics for container port publishing and firewall troubleshooting.
- Added password-authenticated SSH enrichment for Linux and Windows OpenSSH without persisting credentials.
- Added exact hostname, OS, CPU, RAM, and disk inventory export.
- Changed MobaXterm export policy: Windows receives SSH and RDP; Linux receives SSH only; HTTP/HTTPS remain inventory-only.
- Organized MobaXterm sessions beneath Windows and Linux folder trees.
- Fixed Windows CRLF checksum compatibility in the Linux air-gap loader.
