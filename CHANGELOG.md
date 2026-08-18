# Changelog

## 1.2.5

- Renamed the runtime badge to show `NetAtlas version` and the exact running release.
- Added confirmed deletion from Remembered Hosts, available in both the table and host details.
- Added direct IPv4 server targets, which can be scanned alone or alongside VLAN subnets.
- Added password-backed keyboard-interactive SSH fallback and clearer authentication, negotiation, timeout, and restricted-command diagnostics.
- Added per-host SSH shortcuts with the discovered/configured username for MobaXterm or another registered Windows SSH handler; passwords remain excluded.
- Persisted SSH username and diagnostic fields in the remembered-host database and selected inventory CSV.

## 1.2.4

- Added per-column filtering and sortable headers to current and remembered host inventories.
- Added host selection and selected-only inventory, compatibility CSV, and MobaXterm exports.
- Increased the minimum operational font sizes and strengthened contrast in light and dark modes.
- Removed promotional capability and privacy panels that did not help operate the scanner.
- Documented the local `netatlas-data` setup and made the Linux air-gap loader normalize UID/GID 10001 ownership and SELinux labeling automatically.

## 1.2.3

- Increased the GUI type scale, spacing, and table resolution for 1080p and 1440p operations displays.
- Added inferred role names to scan results, host details, inventory CSV, and MobaXterm session comments.
- Added a persistent SQLite-backed Remembered Hosts view that merges resolved hosts across scans.
- Added editable role names; manually assigned roles are preserved when later scans refresh a host.
- Excluded unresolved hostnames from remembered inventory and removed the `.tng.topsecret` suffix from displayed and exported names.

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
