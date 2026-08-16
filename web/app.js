const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const state = { health: null, jobs: [], job: null, timer: null };
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
  const labels = {overview:"Good morning, operator.", results:"Your discovered estate.", configuration:"Define the scan boundary."};
  $("#pageTitle").textContent = labels[view];
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
    await loadHistory();
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
    if (["complete","failed","cancelled"].includes(state.job.status)) { clearInterval(state.timer); state.timer = null; loadHistory(); }
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
    $("#heroText").textContent = "Review the evidence, filter the host inventory, or export all verified connections into MobaXterm."; $("#heroScanButton").textContent = "Run another scan →";
  } else { $("#heroPill").textContent = job.status.toUpperCase(); $("#heroTitle").innerHTML = "Scan stopped.<br><em>Your partial results are safe.</em>"; }
}

function render(job) {
  const s = job.summary || {}; const p = job.progress || 0;
  $("#progressPercent").textContent = `${Math.round(p)}%`; $("#progressBar").style.width = `${p}%`; $("#progressPhase").textContent = job.current_phase;
  $("#progressChecked").textContent = (job.completed || 0).toLocaleString(); $("#progressFound").textContent = (s.hosts || 0).toLocaleString();
  $("#metricHosts").textContent = s.hosts || 0; $("#metricSsh").textContent = s.ssh || 0; $("#metricRdp").textContent = s.rdp || 0; $("#metricWeb").textContent = s.web || 0;
  $("#metricHostsDetail").textContent = job.status === "running" ? `${Math.round(p)}% of scope checked` : job.finished_at ? "Latest completed scan" : "No scan yet";
  $("#navHostCount").textContent = s.hosts || 0; $("#osWindows").textContent = s.windows || 0; $("#osLinux").textContent = s.linux || 0; $("#osUnknown").textContent = s.unknown || 0; $("#donutTotal").textContent = s.hosts || 0;
  const total = Math.max(s.hosts || 0, 1), win = (s.windows || 0) / total * 100, lin = win + (s.linux || 0) / total * 100;
  $("#osDonut").style.setProperty("--win", `${win}%`); $("#osDonut").style.setProperty("--lin", `${lin}%`);
  $("#exportButton").disabled = !(job.results || []).length; renderRecent(job.results || []); renderTable(); updateSites();
  $("#inventoryButton").disabled = !(job.results || []).length;
  if (["complete","failed","cancelled"].includes(job.status)) finishHero(job);
}

function renderRecent(results) {
  const el = $("#recentHosts");
  if (!results.length) { el.className = "recent-hosts empty-state"; el.innerHTML = "<span>⌁</span><h4>No hosts discovered yet</h4><p>Start a scan to build your inventory.</p>"; return; }
  el.className = "recent-hosts"; el.innerHTML = results.slice(-5).reverse().map(host => `<div class="host-row"><span class="host-avatar">${host.os_family === "Windows" ? "W" : host.os_family === "Linux" ? "L" : "?"}</span><div><strong>${esc(host.hostname || host.ip)}</strong><small>${esc(host.ip)}</small></div><div class="service-chips">${host.services.map(serviceChip).join("")}</div><div><strong>${esc(host.site)}</strong><small>${esc(host.vlan)}</small></div></div>`).join("");
}
const serviceChip = x => `<span class="chip ${x}">${esc(x)}</span>`;
const esc = x => String(x ?? "").replace(/[&<>'"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c]));

function resourceText(host) {
  const r = host.resources || {}, parts = [];
  if (r.cpu_cores) parts.push(`${r.cpu_cores} cores`); if (r.ram_gb) parts.push(`${r.ram_gb} GB RAM`);
  if (r.disk_root_gb) parts.push(`${r.disk_root_gb} GB root used/total`); if (r.disk_c_gb) parts.push(`${r.disk_c_gb} GB C:`);
  return parts.length ? parts.join(" · ") : (host.resource_status || "Credentials not supplied");
}
function filteredResults() {
  const q = $("#hostSearch").value.toLowerCase(), site = $("#siteFilter").value, service = $("#serviceFilter").value;
  return (state.job?.results || []).filter(h => (!site || h.site === site) && (!service || h.services.includes(service)) && (!q || [h.hostname,h.ip,h.site,h.vlan,h.os_family,h.os_version].join(" ").toLowerCase().includes(q)));
}
function renderTable() {
  const rows = filteredResults(); $("#resultCount").textContent = `${rows.length} host${rows.length === 1 ? "" : "s"}`;
  $("#hostTable").innerHTML = rows.length ? rows.map(h => `<tr tabindex="0" data-host="${esc(h.ip)}"><td><strong>${esc(h.hostname || "Unresolved")}</strong><small>${esc(h.ip)}</small></td><td><strong>${esc(h.site)}</strong><small>${esc(h.vlan)} · ${esc(h.cidr)}</small></td><td><div class="service-chips">${h.services.map(serviceChip).join("")}</div></td><td><strong>${esc(h.os_version || h.os_family)}</strong><small>${esc(h.os_evidence)}</small></td><td><small>${esc(resourceText(h))}</small></td><td><div class="confidence"><i style="--c:${h.os_confidence || 0}%"></i><span>${h.os_confidence || 0}%</span></div></td><td><span class="row-open">↗</span></td></tr>`).join("") : '<tr><td colspan="7" class="table-empty">No hosts match the current filters.</td></tr>';
  $$('[data-host]').forEach(row => {
    row.addEventListener("click", () => openHost(row.dataset.host));
    row.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openHost(row.dataset.host); }
    });
  });
}

function openHost(ip) {
  const host = (state.job?.results || []).find(item => item.ip === ip);
  if (!host) return;
  const links = [];
  if (host.services.includes("HTTP")) links.push(`<a class="detail-link" href="http://${esc(host.ip)}" target="_blank" rel="noreferrer">Open HTTP ↗</a>`);
  if (host.services.includes("HTTPS")) links.push(`<a class="detail-link" href="https://${esc(host.ip)}" target="_blank" rel="noreferrer">Open HTTPS ↗</a>`);
  const resources = Object.entries(host.resources || {}).map(([key, value]) => `<div class="detail-stat"><small>${esc(key.replaceAll("_", " "))}</small><strong>${esc(value)}</strong></div>`).join("");
  $("#hostDetail").innerHTML = `<div class="host-detail-hero"><p class="eyebrow">${esc(host.site)} · ${esc(host.vlan)}</p><h2>${esc(host.hostname || "Hostname unresolved")}</h2><p>${esc(host.ip)} · ${esc(host.cidr)}</p></div><div class="host-detail-body"><div class="detail-grid"><div class="detail-stat"><small>Operating system</small><strong>${esc(host.os_version || host.os_family)}</strong></div><div class="detail-stat"><small>OS evidence</small><strong>${esc(host.os_evidence)} · ${host.os_confidence || 0}%</strong></div><div class="detail-stat"><small>Hostname source</small><strong>${esc(host.hostname_source || "Unresolved")}</strong></div><div class="detail-stat"><small>Resource status</small><strong>${esc(host.resource_status || "Not collected")}</strong></div></div><div class="detail-section"><h4>Verified connection paths</h4><div class="service-chips">${host.services.map(serviceChip).join("")}</div></div>${resources ? `<div class="detail-section"><h4>Observed resources</h4><div class="detail-grid">${resources}</div></div>` : ""}${links.length ? `<div class="detail-section"><h4>Web consoles</h4><div class="detail-links">${links.join("")}</div></div>` : ""}</div>`;
  $("#hostDialog").showModal();
}
[$("#hostSearch"), $("#siteFilter"), $("#serviceFilter")].forEach(x => x.addEventListener("input", renderTable));
function updateSites() { const current = $("#siteFilter").value, sites = [...new Set((state.job?.results || []).map(x => x.site))].sort(); $("#siteFilter").innerHTML = '<option value="">All sites</option>' + sites.map(x => `<option>${esc(x)}</option>`).join(""); $("#siteFilter").value = current; }

$("#cancelButton").addEventListener("click", async () => { if (state.job) { await api(`/api/scans/${state.job.id}/cancel`, {method:"POST"}); toast("Stopping after current checks finish…"); } });
$("#exportButton").addEventListener("click", () => {
  if (!$("#exportLinuxSshUser").value) $("#exportLinuxSshUser").value = state.job?.config?.linux_ssh_username || "";
  if (!$("#exportWindowsSshUser").value) $("#exportWindowsSshUser").value = state.job?.config?.windows_ssh_username || "";
  $("#exportDialog").showModal();
});
$("#inventoryButton").addEventListener("click", () => { if (state.job) window.location.href = `/api/scans/${state.job.id}/inventory.csv`; });
function download(ext) { if (!state.job) return; const params = new URLSearchParams({linux_ssh_user:$("#exportLinuxSshUser").value, windows_ssh_user:$("#exportWindowsSshUser").value, rdp_user:$("#exportRdpUser").value}); window.location.href = `/api/scans/${state.job.id}/export.${ext}?${params}`; }
$("#downloadMoba").addEventListener("click", () => download("mxtsessions")); $("#downloadCsv").addEventListener("click", () => download("csv"));

async function loadHistory() {
  try { state.jobs = (await api("/api/scans")).sort((a,b) => b.created_at.localeCompare(a.created_at)); renderHistory(); if (!state.job && state.jobs.length) { state.job = state.jobs[0]; render(state.job); if (state.job.status === "running") { showRunning(state.job); state.timer = setInterval(poll, 900); } } } catch (_) {}
}
function renderHistory() { $("#historyList").innerHTML = state.jobs.length ? state.jobs.slice(0,10).map(j => `<div class="history-item"><div><strong>${esc(j.config?.sites?.map(x=>x.name).join(" + ") || "Network scan")}</strong><small>${new Date(j.created_at).toLocaleString()} · ${j.summary.hosts} hosts · ${j.status}</small></div><button data-job="${j.id}">Open</button></div>`).join("") : '<div class="empty-state" style="height:150px"><p>No scan history yet.</p></div>'; $$('[data-job]').forEach(x => x.onclick = () => { state.job = state.jobs.find(j => j.id === x.dataset.job); render(state.job); $("#historyDialog").close(); }); }
$("#historyButton").addEventListener("click", () => $("#historyDialog").showModal());
checkHealth();
