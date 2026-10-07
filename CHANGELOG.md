# Changelog

## 1.2.11

- Added drag handles for system-card ordering; order persists after reload/restart and applies to destinations and exports. Name ordering remains the default until the first manual arrangement.
- Added a checkbox multi-select Systems filter, including Unassigned. Select visible only selects hosts in displayed systems; hidden systems retain their order during a drag.
- Added Delete selected to Remembered Hosts with an explicit confirmation listing selected endpoints, including hidden selections. Backend deletion validates the entire selection and commits atomically.
- Each exported MobaXterm root group receives a random built-in icon; all descendant folders reuse that root icon. Session protocol icons stay unchanged.
- Remembered hosts deduplicate by normalized hostname within a site. Prefer a last octet not ending in 0 (13 over 10, 52 over 50, 107 over 100); ties keep the oldest saved record. Matching names in different sites remain separate, and all-zero-ending alternatives keep one record.
- Duplicate collapse preserves manual roles, system membership/order, red flags and collected OS/resources. Removed duplicate records are archived in SQLite's duplicate_host_archive table. Scan results retain all responding endpoints.
- Background alias discoveries refresh known servers rather than creating duplicate review entries; new multi-IP hosts require one approval, and dismissal applies to their identity.

## 1.2.10

- Clicking Move on a selected Systems host now moves all selected hosts; clicking an unselected host moves just that host.
- Added a sortable, filterable System column to Remembered Hosts and a `system` column to session and inventory CSV exports.
- MobaXterm groups numeric system names such as `99-3` and `392-3` under `RAFAEL`.
- Shared hyphenated system prefixes create parent folders: `RMS-A/B` under `RMS`, `RMS-NP-A/B` under `RMS\NP`, keeping the full system name as the leaf. Selected-only exports retain the same paths using the full catalog.
- All system cards, destination lists, API lists and exports use case-insensitive natural name order instead of creation/manual system order. Host ordering within systems remains adjustable.

## 1.2.9

- Added Show/Hide password controls to manual and background SSH profiles.
- Direct targets now accept individual IPv4 addresses and CIDR scopes (/20–/32) under their own site without a VLAN, including direct-only scans and background scans.
- Scan progress remains below 100% through OS/resource enrichment and inventory updates, reaching 100% only on completion.
- Systems clear selection after successful drops, auto-scroll near screen edges while dragging, and offer a per-server Move to system dialog.
- Recent scans includes labeled background scans. Overview counts, OS groups and site/VLAN groups open the matching remembered list.
- Added persistent red flags for deletion candidates, a counted Red flags tab, and clear-flag actions. Flags do not delete hosts and survive rescans.
- MobaXterm session names use roles, without SSH/RDP suffixes or intermediate OS folders. Duplicate names receive numeric suffixes to retain every session.
- Added role to compatibility CSV exports; inventory CSV already includes it. Existing databases migrate automatically.

## 1.2.8

- Rebuilt Overview entirely from Remembered Hosts, including last-checked reachability, service counts, OS totals, site resources and site/VLAN counts.
- Added dated latest additions to remembered inventory; failed, cancelled or out-of-scope scans do not mark saved hosts offline.
- Added Systems with multi-host drag-and-drop, host ordering, system ordering, rename/delete and selected MobaXterm/CSV exports grouped by system and OS.
- Added persistent interval-based background scans with separate site/VLAN and SSH profiles. Scheduled credentials are encrypted locally and restored after restart.
- Added a New hosts review queue with a live tab count, deduplication, approval and persistent dismissal. Background scans refresh known records without automatically remembering new hosts.
- Preserved previously authenticated OS/resource facts when a later observation cannot collect them.
- Enforced LF shell-script line endings in Git and Windows-created air-gap bundles.

## 1.2.7

- Removed all per-host PuTTY links and the Windows protocol-handler helper.
- Added selected-host MobaXterm and compatibility CSV exports to Remembered Hosts.
- Changed the automatic role default to the resolved hostname while preserving manually edited roles.
- Added editable, persistent site assignment for remembered direct server targets.
- Added Overview rollups for total CPU, RAM, and disk by site; exact OS counts; and server counts for each site/VLAN pair.

## 1.2.6

- Replaced MobaXterm browser shortcuts with PuTTY actions and a downloadable per-user Windows protocol-handler setup; the PuTTY command is copied as a fallback and never contains a password.
- Restored the lightweight 1.2.4 service, RDP, and reverse-DNS discovery path as the default by making deep Nmap inspection opt-in.
- Preserved valid reverse-DNS names when optional RDP/SMB inspection returns alternate identity data.
- Reduced follow-up pressure to four SSH and WinRM workers and two Nmap workers, while adding exactly one fresh retry for transient SSH connection or negotiation failures.
- Added an explicit direct-servers-only mode that ignores populated VLAN lists for that run.

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
