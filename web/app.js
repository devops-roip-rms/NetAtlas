const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const state = {
  health: null, jobs: [], job: null, timer: null, remembered: [], selected: new Set(), selectionJobId: null,
  hostTable: {sortKey: "endpoint", sortDir: "asc", filters: {}},
  rememberedTable: {sortKey: "last_seen", sortDir: "desc", filters: {}}
};
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
  const labels = {overview:"Good morning, operator.", results:"Your discovered estate.", remembered:"Your durable host inventory.", configuration:"Define the scan boundary."};
  $("#pageTitle").textContent = labels[view];
  if (view === "remembered") loadRemembered();
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

function estimate() {
  let count = 0, vlans = 0;
  [$("#siteAVlans").value, $("#siteBVlans").value].forEach(text => parseVlans(text).forEach(v => {
    const bits = Number(v.cidr.split("/")[1]); if (bits >= 20 && bits <= 30) count += Math.max(0, 2 ** (32 - bits) - 2); vlans++;
  }));
  $("#scopeEstimate").textContent = `${count.toLocaleString()} addresses`;
  $("#addressEstimate").textContent = `${vlans} VLANs · up to ${count.toLocaleString()} hosts`;
}
[$("#siteAVlans"), $("#siteBVlans")].forEach(x => x.addEventListener("input", estimate)); estimate();
$("#concurrency").addEventListener("input", e => $("#concurrencyValue").textContent = e.target.value);
$("#sshResources").addEventListener("change", e => $("#sshFields").classList.toggle("show", e.target.checked));
$("#windowsResources").addEventListener("change", e => $("#sslToggle").classList.toggle("hidden", !e.target.checked));

async function checkHealth() {
  try {
    state.health = await api("/api/health");
    $("#backendPulse").classList.add("ok"); $("#backendLabel").textContent = "Local scanner ready";
    const caps = [state.health.nmap ? "Nmap available" : "Nmap optional", state.health.password_ssh ? "Password SSH ready" : "Password SSH unavailable"];
    $("#capabilities").textContent = caps.join(" · ");
    $("#runtimeBadge").innerHTML = `<i></i><span>${state.health.runtime === "container" ? "Docker appliance" : "Local appliance"} · v${esc(state.health.version)}</span>`;
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
    await Promise.all([loadHistory(), loadRemembered()]);
  } catch (_) {
    $("#backendLabel").textContent = "Scanner offline"; $("#capabilities").textContent = "Restart NetAtlas and refresh this page.";
  }
}

function scanConfig() {
  return {
    sites: [
      {name: $("#siteAName").value.trim(), vlans: parseVlans($("#siteAVlans").value)},
      {name: $("#siteBName").value.trim(), vlans: parseVlans($("#siteBVlans").value)}
    ],
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
    if (config.ssh_resources && (linuxPartial || windowsPartial)) throw new Error("Each SSH profile needs both a username and password.");
    if (config.ssh_resources && !profileReady) throw new Error("Configure at least one complete Linux or Windows SSH profile.");
    const job = await api("/api/scans", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(config)});
    $("#linuxSshPassword").value = ""; $("#windowsSshPassword").value = "";
    state.job = job; go("overview"); showRunning(job); clearInterval(state.timer); state.timer = setInterval(poll, 900); poll();
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
    $("#heroPill").innerHTML = "<i></i> INVENTORY CURRENT"; $("#heroTitle").innerHTML = `Discovery complete.<br><em>${job.summary.hosts} endpoints are ready.</em>`;
    $("#heroText").textContent = "Review the evidence, filter any column, select the hosts you need, and export only those connections."; $("#heroScanButton").textContent = "Run another scan →";
  } else { $("#heroPill").textContent = job.status.toUpperCase(); $("#heroTitle").innerHTML = "Scan stopped.<br><em>Your partial results are safe.</em>"; }
}

function render(job) {
  const s = job.summary || {}; const p = job.progress || 0;
  if (state.selectionJobId !== job.id) { state.selected.clear(); state.selectionJobId = job.id; }
  $("#progressPercent").textContent = `${Math.round(p)}%`; $("#progressBar").style.width = `${p}%`; $("#progressPhase").textContent = job.current_phase;
  $("#progressChecked").textContent = (job.completed || 0).toLocaleString(); $("#progressFound").textContent = (s.hosts || 0).toLocaleString();
  $("#metricHosts").textContent = s.hosts || 0; $("#metricSsh").textContent = s.ssh || 0; $("#metricRdp").textContent = s.rdp || 0; $("#metricWeb").textContent = s.web || 0;
  $("#metricHostsDetail").textContent = job.status === "running" ? `${Math.round(p)}% of scope checked` : job.finished_at ? "Latest completed scan" : "No scan yet";
  $("#navHostCount").textContent = s.hosts || 0; $("#osWindows").textContent = s.windows || 0; $("#osLinux").textContent = s.linux || 0; $("#osUnknown").textContent = s.unknown || 0; $("#donutTotal").textContent = s.hosts || 0;
  const total = Math.max(s.hosts || 0, 1), win = (s.windows || 0) / total * 100, lin = win + (s.linux || 0) / total * 100;
  $("#osDonut").style.setProperty("--win", `${win}%`); $("#osDonut").style.setProperty("--lin", `${lin}%`);
  const validKeys = new Set((job.results || []).map(hostKey));
  state.selected = new Set([...state.selected].filter(key => validKeys.has(key)));
  renderRecent(job.results || []); renderTable();
  if (["complete","failed","cancelled"].includes(job.status)) finishHero(job);
}

function renderRecent(results) {
  const el = $("#recentHosts");
  if (!results.length) { el.className = "recent-hosts empty-state"; el.innerHTML = "<span>⌁</span><h4>No hosts discovered yet</h4><p>Start a scan to build your inventory.</p>"; return; }
  el.className = "recent-hosts"; el.innerHTML = results.slice(-5).reverse().map(host => `<div class="host-row"><span class="host-avatar">${host.os_family === "Windows" ? "W" : host.os_family === "Linux" ? "L" : "?"}</span><div><strong>${esc(host.hostname || host.ip)}</strong><small>${esc(host.ip)} · ${esc(host.role || "Network Endpoint")}</small></div><div class="service-chips">${host.services.map(serviceChip).join("")}</div><div><strong>${esc(host.site)}</strong><small>${esc(host.vlan)}</small></div></div>`).join("");
}
const serviceChip = x => `<span class="chip ${x}">${esc(x)}</span>`;
const esc = x => String(x ?? "").replace(/[&<>'"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c]));

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
    if (query && !Object.keys(view.filters).concat(["endpoint", "role", "location", "services", "os", "resources", "confidence", "last_seen", "seen_count"])
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
  $("#hostTable").innerHTML = rows.length ? rows.map(h => `<tr tabindex="0" data-host="${esc(h.ip)}" data-site="${esc(h.site)}"><td class="select-cell"><input type="checkbox" data-host-select="${esc(hostKey(h))}" aria-label="Select ${esc(h.hostname || h.ip)}" ${state.selected.has(hostKey(h)) ? "checked" : ""}></td><td><strong>${esc(h.hostname || "Unresolved")}</strong><small>${esc(h.ip)}</small></td><td><span class="role-pill">${esc(h.role || "Network Endpoint")}</span></td><td><strong>${esc(h.site)}</strong><small>${esc(h.vlan)} · ${esc(h.cidr)}</small></td><td><div class="service-chips">${(h.services || []).map(serviceChip).join("")}</div></td><td><strong>${esc(h.os_version || h.os_family)}</strong><small>${esc(h.os_evidence)}</small></td><td><small>${esc(resourceText(h))}</small></td><td><div class="confidence"><i style="--c:${h.os_confidence || 0}%"></i><span>${h.os_confidence || 0}%</span></div></td><td><span class="row-open">↗</span></td></tr>`).join("") : '<tr><td colspan="9" class="table-empty">No hosts match the current filters.</td></tr>';
  $$('[data-host]').forEach(row => {
    row.addEventListener("click", event => { if (!event.target.closest('input,button')) openHost(row.dataset.host, row.dataset.site); });
    row.addEventListener("keydown", event => {
      if ((event.key === "Enter" || event.key === " ") && !event.target.closest('input,button')) { event.preventDefault(); openHost(row.dataset.host, row.dataset.site); }
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
  const memory = remembered ? `<div class="detail-stat"><small>First seen</small><strong>${esc(new Date(host.first_seen).toLocaleString())}</strong></div><div class="detail-stat"><small>Last seen</small><strong>${esc(new Date(host.last_seen).toLocaleString())} · ${host.seen_count} scans</strong></div>` : "";
  $("#hostDetail").innerHTML = `<div class="host-detail-hero"><p class="eyebrow">${esc(host.site)} · ${esc(host.vlan)}</p><h2>${esc(host.hostname || "Hostname unresolved")}</h2><p>${esc(host.ip)} · ${esc(host.cidr)}</p><span class="detail-role">${esc(host.role || "Network Endpoint")}</span></div><div class="host-detail-body"><div class="detail-grid"><div class="detail-stat"><small>Role</small><strong>${esc(host.role || "Network Endpoint")}</strong></div><div class="detail-stat"><small>Operating system</small><strong>${esc(host.os_version || host.os_family)}</strong></div><div class="detail-stat"><small>OS evidence</small><strong>${esc(host.os_evidence)} · ${host.os_confidence || 0}%</strong></div><div class="detail-stat"><small>Hostname source</small><strong>${esc(host.hostname_source || "Resolved")}</strong></div><div class="detail-stat"><small>Resource status</small><strong>${esc(host.resource_status || "Not collected")}</strong></div>${memory}</div><div class="detail-section"><h4>Verified connection paths</h4><div class="service-chips">${host.services.map(serviceChip).join("")}</div></div>${resources ? `<div class="detail-section"><h4>Observed resources</h4><div class="detail-grid">${resources}</div></div>` : ""}${links.length ? `<div class="detail-section"><h4>Web consoles</h4><div class="detail-links">${links.join("")}</div></div>` : ""}</div>`;
  $("#hostDialog").showModal();
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
  return tableRows(state.remembered, state.rememberedTable, rememberedColumnValue, $("#rememberedSearch").value);
}

function rememberedColumnValue(host, key, raw = false) {
  if (key === "last_seen") return raw ? Date.parse(host.last_seen || 0) : new Date(host.last_seen).toLocaleString();
  if (key === "seen_count") return raw ? Number(host.seen_count || 0) : String(host.seen_count || 0);
  return hostColumnValue(host, key, raw);
}

function renderRemembered() {
  const rows = filteredRemembered();
  $("#navRememberedCount").textContent = state.remembered.length;
  $("#rememberedCount").textContent = `${rows.length} remembered host${rows.length === 1 ? "" : "s"}`;
  $("#rememberedTable").innerHTML = rows.length ? rows.map(host => {
    const index = state.remembered.indexOf(host), seen = new Date(host.last_seen);
    return `<tr tabindex="0" data-remembered-index="${index}"><td><strong>${esc(host.hostname)}</strong><small>${esc(host.ip)}</small></td><td><div class="role-editor"><input data-role-input value="${esc(host.role)}" maxlength="80" aria-label="Role for ${esc(host.hostname)}"><button data-role-save type="button">Save</button></div>${host.role_locked ? '<small class="manual-role">Manual role</small>' : '<small>Auto-detected role</small>'}</td><td><strong>${esc(host.site)}</strong><small>${esc(host.vlan)} · ${esc(host.cidr)}</small></td><td><div class="service-chips">${(host.services || []).map(serviceChip).join("")}</div></td><td><strong>${esc(host.os_version || host.os_family)}</strong><small>${esc(host.os_evidence)}</small></td><td><small>${esc(resourceText(host))}</small></td><td><strong>${esc(seen.toLocaleDateString())}</strong><small>${esc(seen.toLocaleTimeString())}</small></td><td><span class="seen-count">${host.seen_count}</span></td><td><span class="row-open">↗</span></td></tr>`;
  }).join("") : '<tr><td colspan="9" class="table-empty">No resolved hosts match the current filters.</td></tr>';
  $$('[data-remembered-index]').forEach(row => {
    row.addEventListener("click", event => { if (!event.target.closest("input,button")) showHost(state.remembered[Number(row.dataset.rememberedIndex)], true); });
    row.addEventListener("keydown", event => { if ((event.key === "Enter" || event.key === " ") && !event.target.closest("input,button")) { event.preventDefault(); showHost(state.remembered[Number(row.dataset.rememberedIndex)], true); } });
  });
  $$('[data-role-save]').forEach(button => button.addEventListener("click", async event => {
    event.stopPropagation();
    const row = button.closest("tr"), host = state.remembered[Number(row.dataset.rememberedIndex)];
    const role = row.querySelector("[data-role-input]").value.trim();
    if (!role) { toast("Role name cannot be empty."); return; }
    button.disabled = true;
    try {
      const updated = await api("/api/remembered-hosts/role", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({site:host.site, ip:host.ip, role})});
      Object.assign(host, updated); renderRemembered(); toast(`Saved role for ${host.hostname}.`);
    } catch (error) { button.disabled = false; toast(error.message); }
  }));
  $$('[data-role-input]').forEach(input => input.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); input.closest("tr").querySelector("[data-role-save]").click(); } }));
  updateSortButtons("[data-remembered-sort]", state.rememberedTable);
}

async function loadRemembered() {
  try {
    state.remembered = await api("/api/remembered-hosts");
    renderRemembered();
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

$("#cancelButton").addEventListener("click", async () => { if (state.job) { await api(`/api/scans/${state.job.id}/cancel`, {method:"POST"}); toast("Stopping after current checks finish…"); } });
$("#exportButton").addEventListener("click", () => {
  const count = selectedResults().length;
  if (!count) { toast("Select at least one host first."); return; }
  if (!$("#exportLinuxSshUser").value) $("#exportLinuxSshUser").value = state.job?.config?.linux_ssh_username || "";
  if (!$("#exportWindowsSshUser").value) $("#exportWindowsSshUser").value = state.job?.config?.windows_ssh_username || "";
  $("#exportSelectionSummary").textContent = `Creates sessions for ${count} selected host${count === 1 ? "" : "s"} only. Windows receives SSH and RDP; Linux receives SSH.`;
  $("#exportDialog").showModal();
});
async function downloadSelected(format) {
  const hosts = selectedResults();
  if (!state.job || !hosts.length) { toast("Select at least one host first."); return; }
  try {
    const response = await fetch(`/api/scans/${state.job.id}/export`, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({
      format, hosts: hosts.map(host => ({site:host.site, ip:host.ip})),
      linux_ssh_user:$("#exportLinuxSshUser").value, windows_ssh_user:$("#exportWindowsSshUser").value, rdp_user:$("#exportRdpUser").value
    })});
    if (!response.ok) { const error = await response.json(); throw new Error(error.error || `Export failed (${response.status})`); }
    const blob = await response.blob(), url = URL.createObjectURL(blob), link = document.createElement("a");
    const disposition = response.headers.get("Content-Disposition") || "";
    link.href = url; link.download = disposition.match(/filename="?([^";]+)"?/i)?.[1] || `NetAtlas-selected.${format === "inventory" ? "csv" : format}`;
    document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`Exported ${hosts.length} selected host${hosts.length === 1 ? "" : "s"}.`);
  } catch (error) { toast(error.message); }
}
$("#inventoryButton").addEventListener("click", () => downloadSelected("inventory"));
$("#downloadMoba").addEventListener("click", () => downloadSelected("mxtsessions"));
$("#downloadCsv").addEventListener("click", () => downloadSelected("csv"));

async function loadHistory() {
  try { state.jobs = (await api("/api/scans")).sort((a,b) => b.created_at.localeCompare(a.created_at)); renderHistory(); if (!state.job && state.jobs.length) { state.job = state.jobs[0]; render(state.job); if (state.job.status === "running") { showRunning(state.job); state.timer = setInterval(poll, 900); } } } catch (_) {}
}
function renderHistory() { $("#historyList").innerHTML = state.jobs.length ? state.jobs.slice(0,10).map(j => `<div class="history-item"><div><strong>${esc(j.config?.sites?.map(x=>x.name).join(" + ") || "Network scan")}</strong><small>${new Date(j.created_at).toLocaleString()} · ${j.summary.hosts} hosts · ${j.status}</small></div><button data-job="${j.id}">Open</button></div>`).join("") : '<div class="empty-state" style="height:150px"><p>No scan history yet.</p></div>'; $$('[data-job]').forEach(x => x.onclick = () => { state.job = state.jobs.find(j => j.id === x.dataset.job); render(state.job); $("#historyDialog").close(); }); }
$("#historyButton").addEventListener("click", () => $("#historyDialog").showModal());
checkHealth();
