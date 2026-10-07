const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const state = {
  health: null, jobs: [], job: null, timer: null, remembered: [], selected: new Set(), rememberedSelected: new Set(), selectionJobId: null, exportSource: "scan",
  hostTable: {sortKey: "endpoint", sortDir: "asc", filters: {}},
  rememberedTable: {sortKey: "last_seen", sortDir: "desc", filters: {}}
};
Object.assign(state, {systems: [], systemSelected: new Set(), discoveries: [], discoverySelected: new Set(), schedule: null});
state.inventoryGroup = null;
$$('input[type="password"]').forEach(input => {
  const wrapper = document.createElement("div"); wrapper.className = "password-control";
  input.replaceWith(wrapper); wrapper.append(input);
  const button = document.createElement("button"); button.type = "button"; button.className = "password-toggle";
  button.textContent = "Show"; button.setAttribute("aria-controls", input.id); button.setAttribute("aria-pressed", "false");
  button.setAttribute("aria-label", "Show password");
  button.onclick = () => {
    const show = input.type === "password"; input.type = show ? "text" : "password";
    button.textContent = show ? "Hide" : "Show"; button.setAttribute("aria-pressed", String(show)); button.setAttribute("aria-label", show ? "Hide password" : "Show password");
  };
  wrapper.append(button);
});
// Keep scan progress with scan results; Overview only displays remembered inventory.
$("#resultsView").prepend($(".scan-hero"));
const savedTheme = localStorage.getItem("netatlas-theme");
if (savedTheme) document.documentElement.dataset.theme = savedTheme;
$("#themeButton").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("netatlas-theme", next);
});

const defaults = (prefix) => Array.from({length: 10}, (_, i) => `VLAN ${i + 1}, 10.${prefix}.${i + 1}.0/24`).join("\n");
$("#siteAVlans").value = defaults(10);
$("#siteBVlans").value = defaults(20);

function toast(message) {
  const el = $("#toast"); el.textContent = message; el.classList.add("show");
  clearTimeout(el._t); el._t = setTimeout(() => el.classList.remove("show"), 3000);
}

function go(view) {
  $$(".view").forEach(x => x.classList.toggle("active", x.id === `${view}View`));
  $$(".nav-item").forEach(x => x.classList.toggle("active", x.dataset.view === view));
  const labels = {overview:"Your remembered estate.", results:"Your discovered estate.", remembered:"Your durable host inventory.", candidates:"Your deletion candidates.", systems:"Your ordered session library.", discoveries:"Review new discoveries.", background:"Your automatic scan schedule.", configuration:"Define the scan boundary."};
  $("#pageTitle").textContent = labels[view];
  if (["remembered", "overview", "systems", "candidates"].includes(view)) loadRemembered();
  if (view === "discoveries") loadDiscoveries();
  if (view === "background") loadSchedule();
}
$$(".nav-item").forEach(x => x.addEventListener("click", () => go(x.dataset.view)));
$$('[data-go]').forEach(x => x.addEventListener("click", () => go(x.dataset.go)));
[$("#newScanButton"), $("#heroScanButton")].forEach(x => x.addEventListener("click", () => go("configuration")));

async function api(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function parseVlans(text) {
  return text.split(/\r?\n/).map(x => x.trim()).filter(Boolean).map((line, index) => {
    const comma = line.lastIndexOf(",");
    if (comma > -1) return {name: line.slice(0, comma).trim() || `VLAN ${index + 1}`, cidr: line.slice(comma + 1).trim()};
    return {name: `VLAN ${index + 1}`, cidr: line};
  });
}

function parseDirectTargets(text) {
  return text.split(/\r?\n/).map(x => x.trim()).filter(Boolean).map((line, index) => {
    const comma = line.lastIndexOf(",");
    if (comma > -1) return {name: line.slice(0, comma).trim(), ip: line.slice(comma + 1).trim()};
    return {name: "", ip: line};
  });
}

function estimate() {
  let count = 0, vlans = 0;
  const directOnly = $("#directOnly").checked;
  if (!directOnly) {
    [$("#siteAVlans").value, $("#siteBVlans").value].forEach(text => parseVlans(text).forEach(v => {
      const slash = v.cidr.split("/"), bits = slash.length > 1 ? Number(slash[1]) : 32;
      if (bits >= 20 && bits <= 30) count += Math.max(0, 2 ** (32 - bits) - 2);
      else if (bits === 31) count += 2;
      else if (bits === 32) count += 1;
      vlans++;
    }));
  }
  const direct = parseDirectTargets($("#directTargets").value).reduce((count, target) => {
    const bits = Number(target.ip.split("/")[1] ?? 32);
    return count + (bits >= 20 && bits <= 30 ? 2 ** (32-bits)-2 : bits === 31 ? 2 : bits === 32 ? 1 : 0);
  }, 0);
  count += direct;
  $("#scopeEstimate").textContent = `${count.toLocaleString()} ${count === 1 ? "address" : "addresses"}`;
  $("#addressEstimate").textContent = directOnly ? `${direct.toLocaleString()} direct addresses` : `${vlans} ${vlans === 1 ? "VLAN" : "VLANs"}${direct ? ` + ${direct.toLocaleString()} direct addresses` : ""} · up to ${count.toLocaleString()} ${count === 1 ? "host" : "hosts"}`;
  $$("#scanForm .config-card").forEach(card => card.classList.toggle("scope-disabled", directOnly));
  $$("#scanForm .config-card input, #scanForm .config-card textarea").forEach(control => control.disabled = directOnly);
  $("#startScanButton").firstChild.textContent = directOnly ? "Scan direct servers " : "Start discovery ";
}
[$("#siteAVlans"), $("#siteBVlans"), $("#directTargets")].forEach(x => x.addEventListener("input", estimate));
$("#directOnly").addEventListener("change", estimate); estimate();
$("#concurrency").addEventListener("input", e => $("#concurrencyValue").textContent = e.target.value);
$("#sshResources").addEventListener("change", e => $("#sshFields").classList.toggle("show", e.target.checked));
$("#windowsResources").addEventListener("change", e => $("#sslToggle").classList.toggle("hidden", !e.target.checked));

async function checkHealth() {
  try {
    state.health = await api("/api/health");
    $("#backendPulse").classList.add("ok"); $("#backendLabel").textContent = "Local scanner ready";
    const caps = [state.health.nmap ? "Nmap available" : "Nmap optional", state.health.password_ssh ? "Password SSH ready" : "Password SSH unavailable"];
    $("#capabilities").textContent = caps.join(" · ");
    $("#runtimeBadge").innerHTML = `<i></i><span>NetAtlas version ${esc(state.health.version)}</span>`;
    if (!state.health.winrm) {
      $("#windowsResources").disabled = true;
      $("#winrmOption").classList.add("disabled-option");
      $("#winrmHelp").textContent = "Use Windows OpenSSH enrichment in Docker";
    }
    if (!state.health.password_ssh) {
      $("#sshResources").disabled = true;
      $("#sshAuthOption").classList.add("disabled-option");
      $("#sshAuthHelp").textContent = "Install requirements or use the Docker image";
    }
    await Promise.all([loadHistory(), loadRemembered(), loadDiscoveries(), loadSchedule(true)]);
  } catch (_) {
    $("#backendLabel").textContent = "Scanner offline"; $("#capabilities").textContent = "Restart NetAtlas and refresh this page.";
  }
}

function scanConfig() {
  const directOnly = $("#directOnly").checked;
  return {
    scan_mode: directOnly ? "direct_only" : "combined",
    sites: [
      {name: $("#siteAName").value.trim(), vlans: parseVlans($("#siteAVlans").value)},
      {name: $("#siteBName").value.trim(), vlans: parseVlans($("#siteBVlans").value)}
    ],
    direct_target_group: $("#directTargetGroup").value.trim() || "Direct targets",
    direct_targets: parseDirectTargets($("#directTargets").value),
    concurrency: Number($("#concurrency").value), timeout: Number($("#timeout").value),
    auxiliary_ports: $("#auxiliary").checked, deep_scan: $("#deepScan").checked,
    ssh_resources: $("#sshResources").checked,
    linux_ssh_username: $("#linuxSshUsername").value.trim(), linux_ssh_password: $("#linuxSshPassword").value,
    windows_ssh_username: $("#windowsSshUsername").value.trim(), windows_ssh_password: $("#windowsSshPassword").value,
    windows_resources: $("#windowsResources").checked, winrm_ssl: $("#winrmSsl").checked
  };
}

$("#scanForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if ($("#deepScan").checked && state.health && !state.health.nmap) { toast("Nmap is not installed; the scan will use lightweight fingerprints."); }
  try {
    const config = scanConfig();
    const linuxPartial = Boolean(config.linux_ssh_username) !== Boolean(config.linux_ssh_password);
    const windowsPartial = Boolean(config.windows_ssh_username) !== Boolean(config.windows_ssh_password);
    const profileReady = (config.linux_ssh_username && config.linux_ssh_password) || (config.windows_ssh_username && config.windows_ssh_password);
    if (config.scan_mode === "direct_only" && !config.direct_targets.length) throw new Error("Add at least one direct server IP for a direct-only scan.");
    if (config.ssh_resources && (linuxPartial || windowsPartial)) throw new Error("Each SSH profile needs both a username and password.");
    if (config.ssh_resources && !profileReady) throw new Error("Configure at least one complete Linux or Windows SSH profile.");
    const job = await api("/api/scans", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(config)});
    $("#linuxSshPassword").value = ""; $("#windowsSshPassword").value = "";
    state.job = job; go("results"); showRunning(job); clearInterval(state.timer); state.timer = setInterval(poll, 900); poll();
  } catch (error) { toast(error.message); }
});

async function poll() {
  if (!state.job) return;
  try {
    state.job = await api(`/api/scans/${state.job.id}`); render(state.job);
    if (["complete","failed","cancelled"].includes(state.job.status)) { clearInterval(state.timer); state.timer = null; Promise.all([loadHistory(), loadRemembered()]); }
  } catch (error) { clearInterval(state.timer); toast(error.message); }
}

function showRunning(job) {
  $("#progressPanel").classList.remove("hidden"); $("#heroPill").innerHTML = "<i></i> DISCOVERY IN PROGRESS";
  $("#heroTitle").innerHTML = "Mapping your network,<br><em>one endpoint at a time.</em>";
  $("#heroText").textContent = "Results appear as services answer. You can move around the app while discovery continues.";
  $("#heroScanButton").classList.add("hidden"); $("#addressEstimate").classList.add("hidden"); render(job);
}

function finishHero(job) {
  $("#progressPanel").classList.add("hidden"); $("#heroScanButton").classList.remove("hidden"); $("#addressEstimate").classList.remove("hidden");
  if (job.status === "complete") {
    $("#heroPill").innerHTML = "<i></i> INVENTORY CURRENT"; $("#heroTitle").innerHTML = `Discovery complete.<br><em>${job.summary.hosts} ${job.summary.hosts === 1 ? "endpoint is" : "endpoints are"} ready.</em>`;
    $("#heroText").textContent = "Review the evidence, filter any column, select the hosts you need, and export only those connections."; $("#heroScanButton").textContent = "Run another scan →";
  } else { $("#heroPill").textContent = job.status.toUpperCase(); $("#heroTitle").innerHTML = "Scan stopped.<br><em>Your partial results are safe.</em>"; }
}

function render(job) {
  const s = job.summary || {}; const p = job.progress || 0;
  if (state.selectionJobId !== job.id) { state.selected.clear(); state.selectionJobId = job.id; }
  $("#progressPercent").textContent = `${job.status === "complete" && job.finished_at ? 100 : Math.min(99, Math.round(p))}%`; $("#progressBar").style.width = `${p}%`; $("#progressPhase").textContent = job.current_phase;
  $("#progressChecked").textContent = (job.completed || 0).toLocaleString(); $("#progressFound").textContent = (s.hosts || 0).toLocaleString();
  $("#navHostCount").textContent = s.hosts || 0;
  const validKeys = new Set((job.results || []).map(hostKey));
  state.selected = new Set([...state.selected].filter(key => validKeys.has(key)));
  renderTable();
  if (["complete","failed","cancelled"].includes(job.status)) finishHero(job);
}

function renderOverview(data) {
  const s = data.summary, services = data.reachable_services;
  $("#metricRemembered").textContent = s.hosts;
  $("#metricHosts").textContent = s.reachable; $("#metricOffline").textContent = s.unreachable;
  $("#metricUnchecked").textContent = `${s.unchecked} unchecked`;
  $("#metricSsh").textContent = services.ssh; $("#metricRdp").textContent = services.rdp; $("#metricWeb").textContent = services.web;
  $("#overviewChecked").textContent = `All totals use Remembered Hosts. Reachability is from each host's last completed check${data.last_checked ? `; latest check ${new Date(data.last_checked).toLocaleString()}` : ""}.`;
  $("#osWindows").textContent = s.windows; $("#osLinux").textContent = s.linux; $("#osUnknown").textContent = s.unknown; $("#donutTotal").textContent = s.hosts;
  const total = Math.max(s.hosts, 1), win = s.windows / total * 100, lin = win + s.linux / total * 100;
  $("#osDonut").style.setProperty("--win", `${win}%`); $("#osDonut").style.setProperty("--lin", `${lin}%`);
  renderRecent(data.latest_added); renderBreakdowns(data.breakdown);
}

function renderRecent(results) {
  const el = $("#recentHosts");
  if (!results.length) { el.className = "recent-hosts empty-state"; el.innerHTML = "<span>★</span><h4>No remembered hosts yet</h4><p>Run a manual scan or approve background discoveries.</p>"; return; }
  el.className = "recent-hosts"; el.innerHTML = results.map((host, index) => `<button class="host-row recent-memory" data-recent="${index}"><span class="host-avatar">${host.os_family === "Windows" ? "W" : host.os_family === "Linux" ? "L" : "?"}</span><div><strong>${esc(host.hostname)}</strong><small>${esc(host.ip)} · ${esc(host.site)}</small></div><div><strong>${esc(new Date(host.added_at).toLocaleDateString())}</strong><small>${esc(new Date(host.added_at).toLocaleTimeString())} · added to Remembered</small></div></button>`).join("");
  $$('[data-recent]').forEach(button => button.onclick = () => showHost(results[Number(button.dataset.recent)], true));
}

function renderBreakdowns(breakdown) {
  const sites = breakdown.sites || [], operatingSystems = breakdown.operating_systems || [], vlans = breakdown.vlans || [];
  $("#siteResources").classList.toggle("empty-breakdown", !sites.length);
  $("#siteResources").innerHTML = sites.length ? sites.map(site => {
    const capacity = site.resource_hosts ? `${Number(site.cpu_cores || 0).toLocaleString()} cores · ${Number(site.ram_gb || 0).toLocaleString()} GB RAM · ${Number(site.disk_gb || 0).toLocaleString()} GB disk` : "No authenticated resource data";
    return `<button type="button" class="breakdown-row group-button" data-site-group="${esc(site.site)}"><div><strong>${esc(site.site)}</strong><small>${esc(capacity)} · ${site.resource_hosts || 0}/${site.servers} servers measured</small></div><b>${site.servers}</b></button>`;
  }).join("") : "No collected resources yet.";
  $("#osCounts").classList.toggle("empty-breakdown", !operatingSystems.length);
  $("#osCounts").innerHTML = operatingSystems.length ? operatingSystems.map(os => `<button type="button" class="breakdown-row group-button" data-os-group="${esc(os.name)}"><div><strong>${esc(os.name)}</strong><small>Open matching Remembered Hosts →</small></div><b>${os.servers}</b></button>`).join("") : "No operating systems yet.";
  $("#vlanCounts").classList.toggle("empty-breakdown", !vlans.length);
  $("#vlanCounts").innerHTML = vlans.length ? vlans.map(item => `<button type="button" class="breakdown-row group-button" data-vlan-group="${esc(item.vlan)}" data-group-site="${esc(item.site)}"><div><strong>${esc(item.site)} · ${esc(item.vlan)}</strong><small>Open this site's servers →</small></div><b>${item.servers}</b></button>`).join("") : "No VLAN inventory yet.";
  $$('[data-os-group]').forEach(button => button.onclick = () => openInventoryGroup({type:"os", value:button.dataset.osGroup, label:button.dataset.osGroup}));
  $$('[data-site-group]').forEach(button => button.onclick = () => openInventoryGroup({type:"site", value:button.dataset.siteGroup, label:button.dataset.siteGroup}));
  $$('[data-vlan-group]').forEach(button => button.onclick = () => openInventoryGroup({type:"vlan", value:button.dataset.vlanGroup, site:button.dataset.groupSite, label:`${button.dataset.groupSite} · ${button.dataset.vlanGroup}`}));
}
function groupMatches(host) {
  const group = state.inventoryGroup;
  if (!group) return true;
  if (group.type === "os") return (host.os_version || host.os_family || "Unknown") === group.value;
  if (group.type === "family") return group.value === "other" ? !["Windows", "Linux"].includes(host.os_family) : host.os_family === group.value;
  if (group.type === "site") return host.site === group.value;
  if (group.type === "vlan") return host.site === group.site && (host.vlan || "No VLAN") === group.value;
  if (group.type === "status") return group.value === "reachable" ? host.reachable === 1 : host.reachable === 0;
  if (group.type === "service") return host.reachable === 1 && (group.value === "Web" ? host.services.some(service => ["HTTP", "HTTPS"].includes(service)) : host.services.includes(group.value));
  return true;
}
function openInventoryGroup(group) {
  state.inventoryGroup = group; state.rememberedTable.filters = {}; $("#rememberedSearch").value = "";
  $$('[data-remembered-filter]').forEach(input => input.value = "");
  state.rememberedSelected.clear(); go("remembered"); renderRemembered();
}
$("#clearInventoryGroup").onclick = () => { state.inventoryGroup = null; renderRemembered(); };
$$('[data-os-family]').forEach(button => button.onclick = () => openInventoryGroup({type:"family", value:button.dataset.osFamily, label:button.dataset.osFamily === "other" ? "Unknown / other OS" : button.dataset.osFamily}));
for (const [id, group] of [["metricRemembered", null], ["metricHosts", {type:"status", value:"reachable", label:"Reachable hosts"}], ["metricOffline", {type:"status", value:"offline", label:"Unreachable hosts"}], ...["SSH", "RDP", "Web"].map(value => [value === "SSH" ? "metricSsh" : value === "RDP" ? "metricRdp" : "metricWeb", {type:"service",value,label:value}])]) {
  const card = $("#" + id).closest("article"); card.classList.add("clickable-metric"); card.tabIndex = 0; card.setAttribute("role", "button");
  card.onclick = () => openInventoryGroup(group); card.onkeydown = event => { if (["Enter", " "].includes(event.key)) { event.preventDefault(); openInventoryGroup(group); } };
}
const serviceChip = x => `<span class="chip ${x}">${esc(x)}</span>`;
const esc = x => String(x ?? "").replace(/[&<>'"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c]));

function sshUsernameFor(host) {
  if (host.ssh_username) return host.ssh_username;
  const config = state.job?.config || {};
  if (host.os_family === "Windows") return config.windows_ssh_username || config.linux_ssh_username || "";
  return config.linux_ssh_username || config.windows_ssh_username || "";
}

function resourceText(host) {
  const r = host.resources || {}, parts = [];
  if (r.cpu_cores) parts.push(`${r.cpu_cores} cores`); if (r.ram_gb) parts.push(`${r.ram_gb} GB RAM`);
  if (r.disk_root_gb) parts.push(`${r.disk_root_gb} GB root used/total`); if (r.disk_c_gb) parts.push(`${r.disk_c_gb} GB C:`);
  return parts.length ? parts.join(" · ") : (host.resource_status || "Credentials not supplied");
}
const collator = new Intl.Collator(undefined, {numeric: true, sensitivity: "base"});
const hostKey = host => `${host.site || ""}␟${host.ip || ""}`;

function hostColumnValue(host, key, raw = false) {
  const values = {
    endpoint: `${host.hostname || "Unresolved"} ${host.ip || ""}`,
    role: host.role || "Network Endpoint",
    location: `${host.site || ""} ${host.vlan || ""} ${host.cidr || ""}`,
    services: (host.services || []).join(" "),
    os: `${host.os_version || ""} ${host.os_family || ""} ${host.os_evidence || ""}`,
    resources: resourceText(host),
    confidence: raw ? Number(host.os_confidence || 0) : `${host.os_confidence || 0}%`
  };
  return values[key] ?? "";
}

function tableRows(rows, view, valueFor, globalQuery = "") {
  const query = globalQuery.trim().toLowerCase();
  const filtered = rows.filter(host => {
    if (query && !Object.keys(view.filters).concat(["endpoint", "role", "system", "location", "services", "os", "resources", "confidence", "last_seen", "seen_count"])
      .some((key, index, all) => all.indexOf(key) === index && String(valueFor(host, key)).toLowerCase().includes(query))) return false;
    return Object.entries(view.filters).every(([key, value]) => !value || String(valueFor(host, key)).toLowerCase().includes(value.toLowerCase()));
  });
  return filtered.map((host, index) => ({host, index})).sort((left, right) => {
    const a = valueFor(left.host, view.sortKey, true), b = valueFor(right.host, view.sortKey, true);
    const compared = typeof a === "number" && typeof b === "number" ? a - b : collator.compare(String(a), String(b));
    return (compared || left.index - right.index) * (view.sortDir === "asc" ? 1 : -1);
  }).map(item => item.host);
}

function filteredResults() {
  return tableRows(state.job?.results || [], state.hostTable, hostColumnValue, $("#hostSearch").value);
}

function selectedResults() {
  return (state.job?.results || []).filter(host => state.selected.has(hostKey(host)));
}

function updateSortButtons(selector, view) {
  $$(selector).forEach(button => {
    const active = button.dataset.hostSort === view.sortKey || button.dataset.rememberedSort === view.sortKey;
    button.classList.toggle("sort-active", active);
    button.dataset.direction = active ? view.sortDir : "";
  });
}

function updateSelectionControls(rows) {
  const visibleKeys = rows.map(hostKey), selectedCount = selectedResults().length;
  const selectedVisible = visibleKeys.filter(key => state.selected.has(key)).length;
  const selectAll = $("#selectVisible");
  selectAll.checked = visibleKeys.length > 0 && selectedVisible === visibleKeys.length;
  selectAll.indeterminate = selectedVisible > 0 && selectedVisible < visibleKeys.length;
  selectAll.disabled = !visibleKeys.length;
  $("#selectionCount").textContent = `${selectedCount} selected`;
  $("#clearSelectionButton").disabled = selectedCount === 0;
  $("#inventoryButton").disabled = selectedCount === 0;
  $("#exportButton").disabled = selectedCount === 0;
  $("#inventoryButton").textContent = selectedCount ? `CSV selected (${selectedCount})` : "CSV selected";
  $("#exportButton").textContent = selectedCount ? `Export selected (${selectedCount})` : "Export selected";
}

function renderTable() {
  const rows = filteredResults(); $("#resultCount").textContent = `${rows.length} host${rows.length === 1 ? "" : "s"}`;
  $("#hostTable").innerHTML = rows.length ? rows.map(h => `<tr tabindex="0" data-host="${esc(h.ip)}" data-site="${esc(h.site)}"><td class="select-cell"><input type="checkbox" data-host-select="${esc(hostKey(h))}" aria-label="Select ${esc(h.hostname || h.ip)}" ${state.selected.has(hostKey(h)) ? "checked" : ""}></td><td><strong>${esc(h.hostname || "Unresolved")}</strong><small>${esc(h.ip)}</small></td><td><span class="role-pill">${esc(h.role || "Network Endpoint")}</span></td><td><strong>${esc(h.site)}</strong><small>${esc(h.vlan)} · ${esc(h.cidr)}</small></td><td><div class="service-chips">${(h.services || []).map(serviceChip).join("")}</div></td><td><strong>${esc(h.os_version || h.os_family)}</strong><small>${esc(h.os_evidence)}</small></td><td><small>${esc(resourceText(h))}</small></td><td><div class="confidence"><i style="--c:${h.os_confidence || 0}%"></i><span>${h.os_confidence || 0}%</span></div></td><td><div class="row-actions"><span class="row-open">↗</span></div></td></tr>`).join("") : '<tr><td colspan="9" class="table-empty">No hosts match the current filters.</td></tr>';
  $$('[data-host]').forEach(row => {
    row.addEventListener("click", event => { if (!event.target.closest('input,button,a')) openHost(row.dataset.host, row.dataset.site); });
    row.addEventListener("keydown", event => {
      if ((event.key === "Enter" || event.key === " ") && !event.target.closest('input,button,a')) { event.preventDefault(); openHost(row.dataset.host, row.dataset.site); }
    });
  });
  $$('[data-host-select]').forEach(input => input.addEventListener("change", event => {
    event.stopPropagation();
    if (input.checked) state.selected.add(input.dataset.hostSelect); else state.selected.delete(input.dataset.hostSelect);
    updateSelectionControls(rows);
  }));
  updateSortButtons("[data-host-sort]", state.hostTable);
  updateSelectionControls(rows);
}

function openHost(ip, site) {
  const host = (state.job?.results || []).find(item => item.ip === ip && (!site || item.site === site));
  if (!host) return;
  showHost(host);
}

function showHost(host, remembered = false) {
  const links = [];
  if (host.services.includes("HTTP")) links.push(`<a class="detail-link" href="http://${esc(host.ip)}" target="_blank" rel="noreferrer">Open HTTP ↗</a>`);
  if (host.services.includes("HTTPS")) links.push(`<a class="detail-link" href="https://${esc(host.ip)}" target="_blank" rel="noreferrer">Open HTTPS ↗</a>`);
  const resources = Object.entries(host.resources || {}).map(([key, value]) => `<div class="detail-stat"><small>${esc(key.replaceAll("_", " "))}</small><strong>${esc(value)}</strong></div>`).join("");
  const memory = remembered ? `<div class="detail-stat"><small>Added to Remembered</small><strong>${esc(new Date(host.added_at || host.first_seen).toLocaleString())}</strong></div><div class="detail-stat"><small>Last check / status</small><strong>${host.last_checked ? esc(new Date(host.last_checked).toLocaleString()) : "Unchecked"} · ${host.reachable === 1 ? "Reachable" : host.reachable === 0 ? "Unreachable" : "Unknown"}</strong></div><div class="detail-stat"><small>System</small><strong>${esc(host.system_name || "Unassigned")}</strong></div><div class="detail-stat"><small>Last seen</small><strong>${esc(new Date(host.last_seen).toLocaleString())} · ${host.seen_count} sightings</strong></div>` : "";
  const sshDetails = (host.services || []).includes("SSH") ? `<div class="detail-stat"><small>SSH username</small><strong>${esc(sshUsernameFor(host) || "Not configured")}</strong></div><div class="detail-stat"><small>SSH authentication</small><strong>${esc(host.ssh_auth_status || "Not attempted")}${host.ssh_auth_method ? ` · ${esc(host.ssh_auth_method)}` : ""}</strong></div>${host.ssh_auth_error ? `<div class="detail-stat detail-wide"><small>SSH diagnostic</small><strong>${esc(host.ssh_auth_error)}</strong></div>` : ""}` : "";
  const deleteAction = remembered ? `<div class="detail-section danger-zone"><h4>Inventory control</h4><div class="section-actions"><button class="flag-button ${host.deletion_candidate ? "flag-active" : ""}" id="flagRememberedDetail" type="button">${host.deletion_candidate ? "Clear red flag" : "⚑ Mark deletion candidate"}</button><button class="button ghost compact" id="moveRememberedDetail" type="button">Move to system…</button><button class="danger-button" id="deleteRememberedDetail" type="button">Remove from inventory</button></div></div>` : "";
  $("#hostDetail").innerHTML = `<div class="host-detail-hero"><p class="eyebrow">${esc(host.site)} · ${esc(host.vlan)}</p><h2>${esc(host.hostname || "Hostname unresolved")}</h2><p>${esc(host.ip)} · ${esc(host.cidr)}</p><span class="detail-role">${esc(host.role || "Network Endpoint")}</span></div><div class="host-detail-body"><div class="detail-grid"><div class="detail-stat"><small>Role</small><strong>${esc(host.role || "Network Endpoint")}</strong></div><div class="detail-stat"><small>Operating system</small><strong>${esc(host.os_version || host.os_family)}</strong></div><div class="detail-stat"><small>OS evidence</small><strong>${esc(host.os_evidence)} · ${host.os_confidence || 0}%</strong></div><div class="detail-stat"><small>Hostname source</small><strong>${esc(host.hostname_source || "Resolved")}</strong></div><div class="detail-stat"><small>Resource status</small><strong>${esc(host.resource_status || "Not collected")}</strong></div>${sshDetails}${memory}</div><div class="detail-section"><h4>Verified connection paths</h4><div class="service-chips">${host.services.map(serviceChip).join("")}</div></div>${resources ? `<div class="detail-section"><h4>Observed resources</h4><div class="detail-grid">${resources}</div></div>` : ""}${links.length ? `<div class="detail-section"><h4>Connection shortcuts</h4><div class="detail-links">${links.join("")}</div></div>` : ""}${deleteAction}</div>`;
  $("#hostDialog").showModal();
  if (remembered) $("#deleteRememberedDetail").addEventListener("click", () => confirmDeleteRemembered(host));
  if (remembered) $("#flagRememberedDetail").onclick = () => toggleCandidate(host);
  if (remembered) $("#moveRememberedDetail").onclick = () => { $("#hostDialog").close(); openMoveDialog([host]); };
}
$("#hostSearch").addEventListener("input", renderTable);
$$('[data-host-filter]').forEach(input => input.addEventListener("input", () => { state.hostTable.filters[input.dataset.hostFilter] = input.value.trim(); renderTable(); }));
$$('[data-host-sort]').forEach(button => button.addEventListener("click", () => {
  const key = button.dataset.hostSort;
  if (state.hostTable.sortKey === key) state.hostTable.sortDir = state.hostTable.sortDir === "asc" ? "desc" : "asc";
  else { state.hostTable.sortKey = key; state.hostTable.sortDir = "asc"; }
  renderTable();
}));
$("#selectVisible").addEventListener("change", event => {
  filteredResults().forEach(host => event.target.checked ? state.selected.add(hostKey(host)) : state.selected.delete(hostKey(host)));
  renderTable();
});
$("#selectVisibleButton").addEventListener("click", () => { filteredResults().forEach(host => state.selected.add(hostKey(host))); renderTable(); });
$("#clearSelectionButton").addEventListener("click", () => { state.selected.clear(); renderTable(); });

function filteredRemembered() {
  return tableRows(state.remembered.filter(groupMatches), state.rememberedTable, rememberedColumnValue, $("#rememberedSearch").value);
}

function rememberedColumnValue(host, key, raw = false) {
  if (key === "system") return host.system_name || "Unassigned";
  if (key === "last_seen") return raw ? Date.parse(host.last_seen || 0) : new Date(host.last_seen).toLocaleString();
  if (key === "seen_count") return raw ? Number(host.seen_count || 0) : String(host.seen_count || 0);
  return hostColumnValue(host, key, raw);
}

function selectedRemembered() {
  return state.remembered.filter(host => state.rememberedSelected.has(hostKey(host)));
}

function updateRememberedSelectionControls(rows) {
  const visibleKeys = rows.map(hostKey), selectedCount = selectedRemembered().length;
  const selectedVisible = visibleKeys.filter(key => state.rememberedSelected.has(key)).length;
  const selectAll = $("#rememberedSelectVisible");
  selectAll.checked = visibleKeys.length > 0 && selectedVisible === visibleKeys.length;
  selectAll.indeterminate = selectedVisible > 0 && selectedVisible < visibleKeys.length;
  selectAll.disabled = !visibleKeys.length;
  $("#rememberedSelectionCount").textContent = `${selectedCount} selected`;
  $("#rememberedClearSelectionButton").disabled = selectedCount === 0;
  $("#rememberedExportButton").disabled = selectedCount === 0;
  $("#rememberedExportButton").textContent = selectedCount ? `Export selected (${selectedCount})` : "Export selected";
}

function renderRemembered() {
  const rows = filteredRemembered();
  $("#inventoryGroupBar").classList.toggle("hidden", !state.inventoryGroup);
  $("#inventoryGroupLabel").textContent = state.inventoryGroup ? `Showing: ${state.inventoryGroup.label}` : "";
  $("#navRememberedCount").textContent = state.remembered.length;
  $("#rememberedCount").textContent = `${rows.length} remembered host${rows.length === 1 ? "" : "s"}`;
  $("#rememberedTable").innerHTML = rows.length ? rows.map(host => {
    const index = state.remembered.indexOf(host), seen = new Date(host.last_seen);
    const direct = host.direct_target || String(host.cidr || "").endsWith("/32");
    const siteCell = direct ? `<div class="site-editor"><input data-site-input value="${esc(host.site)}" maxlength="60" aria-label="Site for ${esc(host.hostname)}"><button data-site-save type="button">Save</button></div><small>${host.site_locked ? "Manual site" : "Direct target site"} · No VLAN · ${esc(host.cidr)}</small>` : `<strong>${esc(host.site)}</strong><small>${esc(host.vlan || "No VLAN")} · ${esc(host.cidr)}</small>`;
    return `<tr tabindex="0" data-remembered-index="${index}" class="${host.deletion_candidate ? "candidate-row" : ""}"><td class="select-cell"><input type="checkbox" data-remembered-select="${esc(hostKey(host))}" aria-label="Select ${esc(host.hostname || host.ip)}" ${state.rememberedSelected.has(hostKey(host)) ? "checked" : ""}></td><td><strong>${host.deletion_candidate ? '<span class="red-flag" title="Deletion candidate">⚑</span> ' : ""}${esc(host.hostname)}</strong><small>${esc(host.ip)}</small></td><td><div class="role-editor"><input data-role-input value="${esc(host.role)}" maxlength="80" aria-label="Role for ${esc(host.hostname)}"><button data-role-save type="button">Save</button></div>${host.role_locked ? '<small class="manual-role">Manual role</small>' : '<small>Defaults to hostname</small>'}</td><td>${siteCell}</td><td><div class="service-chips">${(host.services || []).map(serviceChip).join("")}</div></td><td><strong>${esc(host.os_version || host.os_family)}</strong><small>${esc(host.os_evidence)}</small></td><td><small>${esc(resourceText(host))}</small></td><td><strong>${esc(seen.toLocaleDateString())}</strong><small>${esc(seen.toLocaleTimeString())}</small></td><td><span class="seen-count">${host.seen_count}</span></td><td><div class="row-actions"><button class="flag-button ${host.deletion_candidate ? "flag-active" : ""}" data-flag-remembered type="button" aria-pressed="${Boolean(host.deletion_candidate)}" title="${host.deletion_candidate ? "Clear red flag" : "Mark deletion candidate"}" aria-label="${host.deletion_candidate ? "Clear red flag for" : "Mark deletion candidate:"} ${esc(host.hostname)}">⚑</button><button class="danger-icon" data-delete-remembered type="button" title="Remove from inventory" aria-label="Remove ${esc(host.hostname)} from inventory">×</button><span class="row-open">↗</span></div></td></tr>`;
  }).join("") : '<tr><td colspan="11" class="table-empty">No resolved hosts match the current filters.</td></tr>';
  $$('[data-remembered-index]').forEach(row => {
    const host = state.remembered[Number(row.dataset.rememberedIndex)];
    const systemCell = row.insertCell(3); systemCell.className = "system-cell";
    systemCell.textContent = host.system_name || "Unassigned";
    row.addEventListener("click", event => { if (!event.target.closest("input,button,a")) showHost(state.remembered[Number(row.dataset.rememberedIndex)], true); });
    row.addEventListener("keydown", event => { if ((event.key === "Enter" || event.key === " ") && !event.target.closest("input,button,a")) { event.preventDefault(); showHost(state.remembered[Number(row.dataset.rememberedIndex)], true); } });
  });
  $$('[data-role-save]').forEach(button => button.addEventListener("click", async event => {
    event.stopPropagation();
    const row = button.closest("tr"), host = state.remembered[Number(row.dataset.rememberedIndex)];
    const role = row.querySelector("[data-role-input]").value.trim();
    if (!role) { toast("Role name cannot be empty."); return; }
    button.disabled = true;
    try {
      const updated = await api("/api/remembered-hosts/role", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({site:host.site, ip:host.ip, role})});
      Object.assign(host, updated); await loadRemembered(); toast(`Saved role for ${host.hostname}.`);
    } catch (error) { button.disabled = false; toast(error.message); }
  }));
  $$('[data-role-input]').forEach(input => input.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); input.closest("tr").querySelector("[data-role-save]").click(); } }));
  $$('[data-site-save]').forEach(button => button.addEventListener("click", async event => {
    event.stopPropagation();
    const row = button.closest("tr"), host = state.remembered[Number(row.dataset.rememberedIndex)];
    const newSite = row.querySelector("[data-site-input]").value.trim(), oldKey = hostKey(host);
    if (!newSite) { toast("Site name cannot be empty."); return; }
    button.disabled = true;
    try {
      const updated = await api("/api/remembered-hosts/site", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({site:host.site, ip:host.ip, new_site:newSite})});
      const wasSelected = state.rememberedSelected.delete(oldKey);
      const systemWasSelected = state.systemSelected.delete(oldKey);
      Object.assign(host, updated);
      if (wasSelected) state.rememberedSelected.add(hostKey(host));
      if (systemWasSelected) state.systemSelected.add(hostKey(host));
      await loadRemembered(); toast(`Moved ${host.hostname} to ${host.site}.`);
    } catch (error) { button.disabled = false; toast(error.message); }
  }));
  $$('[data-site-input]').forEach(input => input.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); input.closest("tr").querySelector("[data-site-save]").click(); } }));
  $$('[data-remembered-select]').forEach(input => input.addEventListener("change", event => {
    event.stopPropagation();
    if (input.checked) state.rememberedSelected.add(input.dataset.rememberedSelect); else state.rememberedSelected.delete(input.dataset.rememberedSelect);
    updateRememberedSelectionControls(rows);
  }));
  $$('[data-delete-remembered]').forEach(button => button.addEventListener("click", event => {
    event.stopPropagation();
    const row = button.closest("tr"), host = state.remembered[Number(row.dataset.rememberedIndex)];
    confirmDeleteRemembered(host);
  }));
  $$('[data-flag-remembered]').forEach(button => button.onclick = event => {
    event.stopPropagation(); toggleCandidate(state.remembered[Number(button.closest("tr").dataset.rememberedIndex)]);
  });
  updateSortButtons("[data-remembered-sort]", state.rememberedTable);
  updateRememberedSelectionControls(rows);
}

async function confirmDeleteRemembered(host) {
  if (!host) return;
  const label = host.hostname || host.ip;
  if (!window.confirm(`Remove ${label} (${host.ip}) from Remembered Hosts?\n\nThis cannot be undone. A later scan may add it again.`)) return;
  try {
    await api("/api/remembered-hosts/delete", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({site:host.site, ip:host.ip})});
    state.rememberedSelected.delete(hostKey(host));
    state.remembered = state.remembered.filter(item => !(item.site === host.site && item.ip === host.ip));
    if ($("#hostDialog").open) $("#hostDialog").close();
    await loadRemembered();
    toast(`Removed ${label} from inventory.`);
  } catch (error) { toast(error.message); }
}

async function loadRemembered() {
  try {
    const [hosts, overview, systems] = await Promise.all([api("/api/remembered-hosts"), api("/api/overview"), api("/api/systems")]);
    state.remembered = hosts; state.systems = systems.sort((a,b) => collator.compare(a.name,b.name));
    const validKeys = new Set(state.remembered.map(hostKey));
    state.rememberedSelected = new Set([...state.rememberedSelected].filter(key => validKeys.has(key)));
    state.systemSelected = new Set([...state.systemSelected].filter(key => validKeys.has(key)));
    renderRemembered(); renderOverview(overview); renderSystems(); renderCandidates();
  } catch (error) { toast(`Remembered hosts unavailable: ${error.message}`); }
}
$("#rememberedSearch").addEventListener("input", renderRemembered);
$$('[data-remembered-filter]').forEach(input => input.addEventListener("input", () => { state.rememberedTable.filters[input.dataset.rememberedFilter] = input.value.trim(); renderRemembered(); }));
$$('[data-remembered-sort]').forEach(button => button.addEventListener("click", () => {
  const key = button.dataset.rememberedSort;
  if (state.rememberedTable.sortKey === key) state.rememberedTable.sortDir = state.rememberedTable.sortDir === "asc" ? "desc" : "asc";
  else { state.rememberedTable.sortKey = key; state.rememberedTable.sortDir = "asc"; }
  renderRemembered();
}));
$("#rememberedSelectVisible").addEventListener("change", event => {
  filteredRemembered().forEach(host => event.target.checked ? state.rememberedSelected.add(hostKey(host)) : state.rememberedSelected.delete(hostKey(host)));
  renderRemembered();
});
$("#rememberedSelectVisibleButton").addEventListener("click", () => { filteredRemembered().forEach(host => state.rememberedSelected.add(hostKey(host))); renderRemembered(); });
$("#rememberedClearSelectionButton").addEventListener("click", () => { state.rememberedSelected.clear(); renderRemembered(); });

$("#cancelButton").addEventListener("click", async () => { if (state.job) { await api(`/api/scans/${state.job.id}/cancel`, {method:"POST"}); toast("Stopping after current checks finish…"); } });
function openExportDialog(source) {
  const count = exportHosts(source).length;
  if (!count) { toast("Select at least one host first."); return; }
  state.exportSource = source;
  if (!$("#exportLinuxSshUser").value) $("#exportLinuxSshUser").value = state.job?.config?.linux_ssh_username || "";
  if (!$("#exportWindowsSshUser").value) $("#exportWindowsSshUser").value = state.job?.config?.windows_ssh_username || "";
  $("#exportSelectionSummary").textContent = `Creates role-named sessions for ${count} selected host${count === 1 ? "" : "s"}.${source !== "scan" ? " Systems are grouped under shared system/environment parents; numeric systems sit under RAFAEL. CSV includes the system name." : ""} Windows receives SSH and RDP; Linux receives SSH. Duplicate role names receive a numeric suffix.`;
  $("#exportDialog").showModal();
}
$("#exportButton").addEventListener("click", () => openExportDialog("scan"));
$("#rememberedExportButton").addEventListener("click", () => openExportDialog("remembered"));
async function downloadSelected(format, source = state.exportSource) {
  const hosts = exportHosts(source);
  if (!hosts.length || (source === "scan" && !state.job)) { toast("Select at least one host first."); return; }
  try {
    const endpoint = source !== "scan" ? "/api/remembered-hosts/export" : `/api/scans/${state.job.id}/export`;
    const response = await fetch(endpoint, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({
      format, hosts: hosts.map(host => ({site:host.site, ip:host.ip})),
      linux_ssh_user:$("#exportLinuxSshUser").value, windows_ssh_user:$("#exportWindowsSshUser").value, rdp_user:$("#exportRdpUser").value
    })});
    if (!response.ok) { const error = await response.json(); throw new Error(error.error || `Export failed (${response.status})`); }
    const blob = await response.blob(), url = URL.createObjectURL(blob), link = document.createElement("a");
    const disposition = response.headers.get("Content-Disposition") || "";
    link.href = url; link.download = disposition.match(/filename="?([^";]+)"?/i)?.[1] || `NetAtlas-${source}-selected.${format === "inventory" ? "csv" : format}`;
    document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`Exported ${hosts.length} selected host${hosts.length === 1 ? "" : "s"}.`);
  } catch (error) { toast(error.message); }
}
$("#inventoryButton").addEventListener("click", () => downloadSelected("inventory", "scan"));
$("#downloadMoba").addEventListener("click", () => downloadSelected("mxtsessions"));
$("#downloadCsv").addEventListener("click", () => downloadSelected("csv"));

function exportHosts(source) {
  if (source === "systems") return state.remembered.filter(host => state.systemSelected.has(hostKey(host)));
  return source === "remembered" ? selectedRemembered() : selectedResults();
}

const post = (path, body) => api(path, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)});
const hostSelection = hosts => hosts.map(({site, ip}) => ({site, ip}));
const systemHosts = id => state.remembered.filter(host => (host.system_id || "") === id).sort((a,b) => a.system_position - b.system_position || a.hostname.localeCompare(b.hostname));
const systemGroups = () => [...state.systems, {id:"", name:"Unassigned"}].sort((a,b) => collator.compare(a.name,b.name));
function visibleSystemHosts(id) {
  const query = $("#systemSearch").value.trim().toLowerCase();
  return systemHosts(id).filter(host => !query || `${host.hostname} ${host.ip} ${host.site} ${host.vlan} ${host.role} ${host.os_version} ${host.system_name || "Unassigned"}`.toLowerCase().includes(query));
}
function systemSelectionControls() {
  const count = exportHosts("systems").length;
  $("#systemSelectionCount").textContent = `${count} selected`;
  $("#systemsExportButton").disabled = !count;
  $("#systemMoveButton").disabled = !count;
}
async function moveHosts(id, hosts, position, clearSelection = false) {
  if (!hosts.length) return;
  try {
    await post("/api/systems/move", {system_id:id, hosts:hostSelection(hosts), ...(position == null ? {} : {position})});
    if (clearSelection) state.systemSelected.clear();
    await loadRemembered(); toast(`Saved order for ${hosts.length} host${hosts.length === 1 ? "" : "s"}.`); return true;
  } catch (error) { toast(error.message); return false; }
}
function renderSystems() {
  const groups = systemGroups();
  const oldTarget = $("#systemMoveTarget").value;
  $("#systemMoveTarget").innerHTML = groups.map(system => `<option value="${esc(system.id)}">${esc(system.name)}</option>`).join("");
  if (groups.some(system => system.id === oldTarget)) $("#systemMoveTarget").value = oldTarget;
  $("#systemsBoard").innerHTML = groups.map(system => {
    const hosts = visibleSystemHosts(system.id);
    return `<section class="panel system-card" data-system="${esc(system.id)}"><header><div><h3>${esc(system.name)}</h3><small>${systemHosts(system.id).length} servers · ${hosts.length} visible</small></div><div class="system-actions">${system.id ? `<button class="button ghost compact" data-system-rename>Rename</button><button class="danger-icon" data-system-delete aria-label="Delete system">×</button>` : ""}</div></header><div class="system-hosts">${hosts.map(host => {
      const idx = state.remembered.indexOf(host), checked = state.systemSelected.has(hostKey(host));
      return `<div class="system-host ${checked ? "selected" : ""}" draggable="true" data-system-host="${idx}"><input type="checkbox" ${checked ? "checked" : ""} aria-label="Select ${esc(host.hostname)}"><span class="drag-handle" aria-hidden="true">⠿</span><button class="system-host-open"><strong>${host.deletion_candidate ? '<span class="red-flag">⚑</span> ' : ""}${esc(host.hostname)}</strong><small>${esc(host.role)} · ${esc(host.ip)} · ${esc(host.site)}</small></button><button class="order-button" data-host-move>Move…</button><button class="order-button" data-host-up aria-label="Move host up">↑</button><button class="order-button" data-host-down aria-label="Move host down">↓</button></div>`;
    }).join("") || '<p class="drop-placeholder">Drop servers here, or select servers and use Move selected.</p>'}</div></section>`;
  }).join("");
  $$('[data-system-host]').forEach(row => {
    const host = state.remembered[Number(row.dataset.systemHost)];
    row.querySelector("input").onchange = event => {
      event.target.checked ? state.systemSelected.add(hostKey(host)) : state.systemSelected.delete(hostKey(host));
      row.classList.toggle("selected", event.target.checked); systemSelectionControls();
    };
    row.querySelector(".system-host-open").onclick = () => showHost(host, true);
    row.querySelector("[data-host-move]").onclick = () => openMoveDialog(state.systemSelected.has(hostKey(host)) ? exportHosts("systems") : [host]);
    row.ondragstart = event => {
      state.dragging = true;
      const hosts = state.systemSelected.has(hostKey(host)) ? exportHosts("systems") : [host];
      event.dataTransfer.setData("application/netatlas-hosts", JSON.stringify(hostSelection(hosts)));
      event.dataTransfer.effectAllowed = "move";
    };
    row.ondragend = () => { stopDragScroll(); $$(".drop-active").forEach(el => el.classList.remove("drop-active")); };
    for (const [selector, direction] of [["[data-host-up]", -1], ["[data-host-down]", 1]]) {
      const all = systemHosts(host.system_id || ""), index = all.indexOf(host);
      const button = row.querySelector(selector); button.disabled = index + direction < 0 || index + direction >= all.length;
      button.onclick = () => moveHosts(host.system_id || "", [host], index + direction);
    }
  });
  $$('[data-system]').forEach(card => {
    const id = card.dataset.system;
    card.ondragover = event => { if (event.dataTransfer.types.includes("application/netatlas-hosts")) { event.preventDefault(); card.classList.add("drop-active"); } };
    card.ondragleave = event => { if (!card.contains(event.relatedTarget)) card.classList.remove("drop-active"); };
    card.ondrop = event => {
      event.preventDefault(); card.classList.remove("drop-active"); stopDragScroll();
      try {
        const selection = JSON.parse(event.dataTransfer.getData("application/netatlas-hosts"));
        const keys = new Set(selection.map(hostKey)), hosts = state.remembered.filter(host => keys.has(hostKey(host)));
        const targetRow = event.target.closest("[data-system-host]");
        const target = targetRow ? state.remembered[Number(targetRow.dataset.systemHost)] : null;
        const remaining = systemHosts(id).filter(host => !keys.has(hostKey(host)));
        if (target && keys.has(hostKey(target))) return;
        moveHosts(id, hosts, target ? remaining.indexOf(target) : remaining.length, true);
      } catch (_) { toast("Drag remembered servers into a system."); }
    };
    if (!id) return;
    card.querySelector("[data-system-rename]").onclick = async () => {
      const name = window.prompt("System name", state.systems.find(system => system.id === id).name);
      if (!name?.trim()) return;
      try { await post("/api/systems", {action:"rename", id, name}); await loadRemembered(); } catch (error) { toast(error.message); }
    };
    card.querySelector("[data-system-delete]").onclick = async () => {
      if (!window.confirm("Delete this system? Its hosts will move to Unassigned and remain remembered.")) return;
      try { await post("/api/systems", {action:"delete", id}); await loadRemembered(); } catch (error) { toast(error.message); }
    };
  });
  systemSelectionControls();
}
$("#newSystemForm").onsubmit = async event => {
  event.preventDefault();
  try { await post("/api/systems", {name:$("#newSystemName").value}); $("#newSystemName").value = ""; await loadRemembered(); } catch (error) { toast(error.message); }
};
$("#systemSearch").oninput = renderSystems;
$("#systemSelectAll").onclick = () => { [...state.systems, {id:""}].flatMap(system => visibleSystemHosts(system.id)).forEach(host => state.systemSelected.add(hostKey(host))); renderSystems(); };
$("#systemClear").onclick = () => { state.systemSelected.clear(); renderSystems(); };
$("#systemMoveButton").onclick = () => moveHosts($("#systemMoveTarget").value, exportHosts("systems"), undefined, true);
$("#systemsExportButton").onclick = () => openExportDialog("systems");

function stopDragScroll() {
  state.dragging = false; state.dragScrollSpeed = 0;
  if (state.dragScrollFrame) cancelAnimationFrame(state.dragScrollFrame);
  state.dragScrollFrame = null;
}
function dragScrollTick() {
  state.dragScrollFrame = null;
  if (!state.dragging || !state.dragScrollSpeed) return;
  window.scrollBy(0, state.dragScrollSpeed);
  state.dragScrollFrame = requestAnimationFrame(dragScrollTick);
}
document.addEventListener("dragover", event => {
  if (!state.dragging) return;
  const edge = 100, y = event.clientY, height = window.innerHeight;
  state.dragScrollSpeed = y < edge ? -Math.ceil(24 * (1-y/edge)) : y > height-edge ? Math.ceil(24 * (1-(height-y)/edge)) : 0;
  if (state.dragScrollSpeed && !state.dragScrollFrame) state.dragScrollFrame = requestAnimationFrame(dragScrollTick);
});
document.addEventListener("drop", stopDragScroll);
document.addEventListener("dragend", stopDragScroll);
window.addEventListener("blur", stopDragScroll);

function openMoveDialog(hosts) {
  if (!hosts.length) return;
  state.pendingMove = hosts;
  $("#moveDialogTarget").innerHTML = systemGroups().map(system => `<option value="${esc(system.id)}">${esc(system.name)}</option>`).join("");
  $("#moveDialogTarget").value = hosts[0].system_id || "";
  $("#moveDialogSummary").textContent = hosts.length === 1 ? `Move ${hosts[0].role || hosts[0].hostname} (${hosts[0].ip}).` : `Move ${hosts.length} servers.`;
  $("#confirmSystemMove").textContent = hosts.length === 1 ? "Move server" : `Move ${hosts.length} servers`;
  $("#moveDialog").showModal();
}
$("#confirmSystemMove").onclick = async () => {
  const button = $("#confirmSystemMove"); button.disabled = true;
  try { if (await moveHosts($("#moveDialogTarget").value, state.pendingMove || [], undefined, true)) $("#moveDialog").close(); }
  finally { button.disabled = false; }
};

async function toggleCandidate(host) {
  if (!host) return;
  try {
    await post("/api/remembered-hosts/flag", {site:host.site, ip:host.ip, flagged:!host.deletion_candidate});
    const detailOpen = $("#hostDialog").open;
    if (detailOpen) $("#hostDialog").close();
    await loadRemembered();
    if (detailOpen) showHost(state.remembered.find(item => hostKey(item) === hostKey(host)), true);
    toast(host.deletion_candidate ? "Red flag cleared." : "Marked as a deletion candidate.");
  } catch (error) { toast(error.message); }
}
function renderCandidates() {
  const flagged = state.remembered.filter(host => host.deletion_candidate).sort((a,b) => (b.flagged_at || "").localeCompare(a.flagged_at || ""));
  $("#navCandidateCount").textContent = flagged.length;
  const query = $("#candidateSearch").value.trim().toLowerCase();
  const hosts = flagged.filter(host => `${host.hostname} ${host.role} ${host.ip} ${host.site} ${host.vlan} ${host.os_version}`.toLowerCase().includes(query));
  $("#candidateCount").textContent = `${hosts.length} flagged hosts`;
  $("#candidateTable").innerHTML = hosts.map((host,index) => `<tr class="candidate-row"><td><button class="candidate-open" data-candidate-open="${index}"><strong>⚑ ${esc(host.hostname)}</strong><small>${esc(host.ip)}</small></button></td><td>${esc(host.role)}</td><td>${esc(host.site)}<small>${esc(host.vlan || "No VLAN")}</small></td><td>${esc(host.os_version || host.os_family)}</td><td>${esc(new Date(host.flagged_at).toLocaleString())}</td><td><div class="row-actions"><button class="flag-button flag-active" data-candidate-clear="${index}">Clear flag</button><button class="danger-button" data-candidate-delete="${index}">Remove from inventory</button></div></td></tr>`).join("") || '<tr><td colspan="6" class="table-empty">No deletion candidates match.</td></tr>';
  $$('[data-candidate-open]').forEach(button => button.onclick = () => showHost(hosts[Number(button.dataset.candidateOpen)], true));
  $$('[data-candidate-clear]').forEach(button => button.onclick = () => toggleCandidate(hosts[Number(button.dataset.candidateClear)]));
  $$('[data-candidate-delete]').forEach(button => button.onclick = () => confirmDeleteRemembered(hosts[Number(button.dataset.candidateDelete)]));
}
$("#candidateSearch").oninput = renderCandidates;

function filteredDiscoveries() {
  const query = $("#discoverySearch").value.trim().toLowerCase();
  return state.discoveries.filter(host => !query || `${host.hostname} ${host.ip} ${host.site} ${host.vlan} ${host.os_version} ${host.services.join(" ")}`.toLowerCase().includes(query));
}
function renderDiscoveries() {
  $("#navDiscoveryCount").textContent = state.discoveries.length;
  const count = state.discoveries.filter(host => state.discoverySelected.has(hostKey(host))).length;
  $("#discoverySelectionCount").textContent = `${count} selected`;
  $("#approveDiscoveries").disabled = !count; $("#dismissDiscoveries").disabled = !count;
  $("#discoveryTable").innerHTML = filteredDiscoveries().map(host => `<tr><td class="select-cell"><input type="checkbox" data-discovery="${state.discoveries.indexOf(host)}" ${state.discoverySelected.has(hostKey(host)) ? "checked" : ""} aria-label="Select ${esc(host.hostname)}"></td><td><strong>${esc(host.hostname)}</strong><small>${esc(host.ip)}</small></td><td>${esc(host.site)}<small>${esc(host.vlan)}</small></td><td><div class="service-chips">${host.services.map(serviceChip).join("")}</div></td><td>${esc(host.os_version || host.os_family)}</td><td>${esc(resourceText(host))}</td><td>${esc(new Date(host.first_seen).toLocaleString())}</td><td>${esc(new Date(host.last_seen).toLocaleString())}</td></tr>`).join("") || '<tr><td colspan="8" class="table-empty">No new resolved hosts awaiting review.</td></tr>';
  $$('[data-discovery]').forEach(input => input.onchange = () => {
    const host = state.discoveries[Number(input.dataset.discovery)];
    input.checked ? state.discoverySelected.add(hostKey(host)) : state.discoverySelected.delete(hostKey(host)); renderDiscoveries();
  });
}
async function loadDiscoveries() {
  try {
    state.discoveries = await api("/api/discoveries");
    const keys = new Set(state.discoveries.map(hostKey));
    state.discoverySelected = new Set([...state.discoverySelected].filter(key => keys.has(key)));
    renderDiscoveries();
  } catch (error) { toast(error.message); }
}
async function reviewDiscoveries(action) {
  const hosts = state.discoveries.filter(host => state.discoverySelected.has(hostKey(host)));
  if (!hosts.length) return;
  if (action === "dismiss" && !window.confirm(`Dismiss ${hosts.length} hosts? Future background scans will keep these hosts hidden.`)) return;
  try {
    await post("/api/discoveries/review", {action, hosts:hostSelection(hosts)});
    state.discoverySelected.clear(); await Promise.all([loadDiscoveries(), loadRemembered()]);
    toast(action === "approve" ? `Added ${hosts.length} hosts to Remembered.` : `Dismissed ${hosts.length} hosts.`);
  } catch (error) { toast(error.message); }
}
$("#discoverySearch").oninput = renderDiscoveries;
$("#discoverySelectAll").onclick = () => { filteredDiscoveries().forEach(host => state.discoverySelected.add(hostKey(host))); renderDiscoveries(); };
$("#discoveryClear").onclick = () => { state.discoverySelected.clear(); renderDiscoveries(); };
$("#discoveryRefresh").onclick = loadDiscoveries;
$("#approveDiscoveries").onclick = () => reviewDiscoveries("approve");
$("#dismissDiscoveries").onclick = () => reviewDiscoveries("dismiss");

function fillSchedule(config) {
  const sites = config.sites || [];
  for (const [index, prefix] of [[0, "A"], [1, "B"]]) {
    $("#bgSite" + prefix + "Name").value = sites[index]?.name || "Site " + prefix;
    $("#bgSite" + prefix + "Vlans").value = (sites[index]?.vlans || []).map(vlan => `${vlan.name}, ${vlan.cidr}`).join("\n");
  }
  $("#bgTimeout").value = config.timeout || 0.5; $("#bgConcurrency").value = config.concurrency || 64;
  $("#bgSshResources").checked = Boolean(config.ssh_resources);
  $("#bgLinuxUser").value = config.linux_ssh_username || ""; $("#bgWindowsUser").value = config.windows_ssh_username || "";
  $("#bgDirectGroup").value = config.direct_target_group || "Direct targets";
  $("#bgDirectTargets").value = (config.direct_targets || []).map(target => target.name ? `${target.name}, ${target.ip || target.cidr}` : target.ip || target.cidr).join("\n");
  $("#bgDirectOnly").checked = config.scan_mode === "direct_only";
}
async function loadSchedule(fill = false) {
  try {
    state.schedule = await api("/api/schedule");
    if (fill) { fillSchedule(state.schedule.config); $("#bgInterval").value = state.schedule.interval_minutes; }
    const s = state.schedule;
    $("#stopSchedule").disabled = !s.enabled && !s.running;
    $("#scheduleStatus").innerHTML = `<strong>${s.enabled ? "Schedule enabled" : "Schedule stopped"}</strong><span>${s.running ? `Scanning · ${Math.round(s.job.progress)}% · ${esc(s.job.phase)}` : s.enabled ? `Next run: ${s.next_run ? new Date(s.next_run * 1000).toLocaleString() : "after active scan finishes"}` : "Save a schedule to start scanning."}</span><small>Interval: ${s.interval_minutes} minutes${s.last_run ? ` · Last finished: ${esc(new Date(s.last_run).toLocaleString())}` : ""}</small>${s.error ? `<p class="schedule-error">${esc(s.error)}</p>` : ""}`;
  } catch (error) { toast(error.message); }
}
$("#copyScanSetup").onclick = () => {
  const config = scanConfig(); fillSchedule(config);
  $("#bgLinuxPassword").value = config.linux_ssh_password; $("#bgWindowsPassword").value = config.windows_ssh_password;
  toast("Copied VLANs and SSH profiles from Scan setup.");
};
$("#scheduleForm").onsubmit = async event => {
  event.preventDefault(); const button = $("#saveSchedule"); button.disabled = true;
  try {
    await post("/api/schedule", {interval_minutes:Number($("#bgInterval").value), config:{
      scan_mode:$("#bgDirectOnly").checked ? "direct_only" : "combined", direct_target_group:$("#bgDirectGroup").value.trim(), direct_targets:parseDirectTargets($("#bgDirectTargets").value),
      sites:[{name:$("#bgSiteAName").value.trim(), vlans:parseVlans($("#bgSiteAVlans").value)}, {name:$("#bgSiteBName").value.trim(), vlans:parseVlans($("#bgSiteBVlans").value)}],
      concurrency:Number($("#bgConcurrency").value), timeout:Number($("#bgTimeout").value), auxiliary_ports:true, ssh_resources:$("#bgSshResources").checked,
      linux_ssh_username:$("#bgLinuxUser").value.trim(), linux_ssh_password:$("#bgLinuxPassword").value,
      windows_ssh_username:$("#bgWindowsUser").value.trim(), windows_ssh_password:$("#bgWindowsPassword").value
    }});
    $("#bgLinuxPassword").value = ""; $("#bgWindowsPassword").value = "";
    await loadSchedule(); toast("Schedule saved. New hosts will wait for your approval.");
  } catch (error) { toast(error.message); } finally { button.disabled = false; }
};
$("#stopSchedule").onclick = async () => {
  try { await post("/api/schedule", {action:"stop"}); await loadSchedule(); toast("Schedule stopped; saved credentials cleared."); } catch (error) { toast(error.message); }
};
setInterval(async () => {
  if (!state.health || state.refreshing || state.dragging || document.activeElement?.matches("input,textarea,select") || $$("dialog[open]").length) return;
  state.refreshing = true;
  try { await Promise.all([loadDiscoveries(), loadSchedule(), loadRemembered()]); } finally { state.refreshing = false; }
}, 5000);

async function loadHistory() {
  try { state.jobs = (await api("/api/scans")).reverse().sort((a,b) => b.created_at.localeCompare(a.created_at)); renderHistory(); if (!state.job && state.jobs.length) { state.job = state.jobs[0]; render(state.job); if (["queued", "running"].includes(state.job.status)) { showRunning(state.job); state.timer = setInterval(poll, 900); } } } catch (_) {}
}
function renderHistory() {
  $("#historyList").innerHTML = state.jobs.length ? state.jobs.slice(0,20).map(job => {
    const names = job.config?.scan_mode === "direct_only" ? job.config.direct_target_group : [...(job.config?.sites || []).filter(site => site.vlans?.length).map(site => site.name), ...(job.config?.direct_targets?.length ? [job.config.direct_target_group || "Direct targets"] : [])].join(" + ");
    return `<div class="history-item"><div><span class="history-type ${job.config?.background_scan ? "background" : ""}">${job.config?.background_scan ? "Background scan" : "Manual scan"}</span><strong>${esc(names || "Network scan")}</strong><small>${new Date(job.created_at).toLocaleString()} · ${job.summary.hosts} hosts · ${job.status}</small></div><button data-job="${job.id}">Open</button></div>`;
  }).join("") : '<div class="empty-state" style="height:150px"><p>No scan history yet.</p></div>';
  $$('[data-job]').forEach(button => button.onclick = async () => {
    try {
      state.job = await api(`/api/scans/${button.dataset.job}`); clearInterval(state.timer); state.timer = null;
      $("#historyDialog").close(); go("results"); render(state.job);
      if (["queued", "running"].includes(state.job.status)) { showRunning(state.job); state.timer = setInterval(poll, 900); }
    } catch (error) { toast(error.message); }
  });
}
$("#historyButton").addEventListener("click", async () => { await loadHistory(); $("#historyDialog").showModal(); });
checkHealth();
