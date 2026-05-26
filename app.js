

const API = "http://localhost:5000/api";

let currentPage = "dashboard";
let chartPie = null, chartBar = null, chartStatus = null;

const pageInfo = {
  dashboard: { title: "Dashboard",          sub: "Overview of all incidents and threats" },
  incidents:  { title: "Incidents",          sub: "All recorded security incidents" },
  alerts:     { title: "Critical Alerts",    sub: "Unacknowledged high-priority alerts" },
  charts:     { title: "Charts & Analytics", sub: "Visual breakdown of threats and incidents" },
  attackers:  { title: "Repeat Attackers",   sub: "IPs with multiple recorded incidents" },
  report:     { title: "Response Report",    sub: "Team performance via stored procedure" },
  audit:      { title: "Audit Log",          sub: "All user actions and system events" },
};


function navigate(page) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  document.getElementById("page-" + page).classList.add("active");
  document.querySelector(`[data-page="${page}"]`).classList.add("active");

  const info = pageInfo[page] || {};
  document.getElementById("page-title").textContent = info.title || page;
  document.getElementById("page-sub").textContent   = info.sub   || "";
  currentPage = page;

  if (page === "dashboard")  { loadStats(); loadDashboard(); }
  if (page === "incidents")  { loadIncidents(); }
  if (page === "alerts")     { loadAlerts(); }
  if (page === "charts")     { loadCharts(); }
  if (page === "attackers")  { loadAttackers(); }
  if (page === "report")     { loadTeams(); loadReport(); }
  if (page === "audit")      { loadAuditLog(); }
}

function refreshCurrent() { navigate(currentPage); toast("Refreshed", "green"); }


async function apiFetch(url) {
  const res  = await fetch(API + url);
  if (res.status === 401) { window.location.href = "/login"; return; }
  const data = await res.json();
  if (!data.success) throw new Error(data.error || "API error");
  return data.data;
}

async function apiPost(url, body) {
  const res = await fetch(API + url, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return await res.json();
}

async function apiPatch(url, body) {
  const res = await fetch(API + url, {
    method: "PATCH", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return await res.json();
}

async function apiDelete(url) {
  const res = await fetch(API + url, { method: "DELETE" });
  return await res.json();
}


function scoreColor(s) {
 
  if (s >= 80) return "#2e1065";
  if (s >= 60) return "#6d28d9";
  return "#8b5cf6";
}
function scoreBarColor(s) {
  if (s >= 80) return "#4c1d95";
  if (s >= 60) return "#7c3aed";
  return "#a78bfa";
}
function statusClass(st) {
  return { "Open":"open", "In Progress":"progress", "Resolved":"resolved", "Closed":"closed" }[st] || "closed";
}
function severityClass(sv) { return (sv||"").toLowerCase(); }
function priorityClass(pf) { return (pf||"").toLowerCase(); }
function fmtDate(dt) {
  if (!dt) return "—";
  return new Date(dt).toLocaleString("en-PK", { dateStyle: "medium", timeStyle: "short" });
}
function scoreBar(score) {
  const c = scoreBarColor(score);
  return `<div class="score-wrap">
    <span class="score-num" style="color:${scoreColor(score)}">${score}</span>
    <div class="bar-track"><div class="bar-fill" style="width:${score}%;background:${c}"></div></div>
  </div>`;
}
function loadingRow(cols) {
  return `<tr class="loading-row"><td colspan="${cols}"><span class="spinner"></span>Loading...</td></tr>`;
}
function emptyRow(cols, msg = "No records found") {
  return `<tr class="empty-row"><td colspan="${cols}">${msg}</td></tr>`;
}


async function loadStats() {
  try {
    const d = await apiFetch("/stats");
    document.getElementById("s-total").textContent  = d.total          ?? "—";
    document.getElementById("s-open").textContent   = d.open_count     ?? "—";
    document.getElementById("s-alerts").textContent = d.unacked_alerts ?? "—";
    document.getElementById("s-avg").textContent    = d.avg_score      ?? "—";
    document.getElementById("nav-open").textContent   = d.open_count     ?? 0;
    document.getElementById("nav-alerts").textContent = d.unacked_alerts ?? 0;
    setConnected(true);
  } catch (e) { setConnected(false); }
}

function setConnected(ok) {
  const dot   = document.getElementById("conn-dot");
  const label = document.getElementById("conn-label");
  dot.className     = "conn-dot " + (ok ? "connected" : "error");
  label.textContent = ok ? "Connected" : "DB Error";
}


async function loadDashboard() {
  const urgent = document.getElementById("urgent-toggle")?.checked;
  const el     = document.getElementById("dashboard-table");
  el.innerHTML = `<table><tbody>${loadingRow(7)}</tbody></table>`;
  try {
    const rows = await apiFetch(`/dashboard?urgent_only=${urgent}`);
    if (!rows.length) { el.innerHTML = `<table><tbody>${emptyRow(7)}</tbody></table>`; return; }
    let html = `<table><thead><tr>
      <th>#</th><th>System</th><th>Attack</th><th>IP</th>
      <th>Score</th><th>Status</th><th>Priority</th>
    </tr></thead><tbody>`;
    rows.forEach(r => {
      html += `<tr>
        <td style="color:var(--muted);font-size:12px;font-weight:800">#${r.incident_id}</td>
        <td>${r.system_name}</td><td>${r.attack_name}</td>
        <td><span class="ip-chip">${r.attacker_ip}</span></td>
        <td>${scoreBar(r.threat_score)}</td>
        <td><span class="badge ${statusClass(r.status)}">${r.status}</span></td>
        <td><span class="badge ${priorityClass(r.priority_flag)}">${r.priority_flag}</span></td>
      </tr>`;
    });
    el.innerHTML = html + "</tbody></table>";
  } catch (e) {
    el.innerHTML = `<table><tbody>${emptyRow(7, "Error: " + e.message)}</tbody></table>`;
  }
}


async function loadIncidents() {
  const status   = document.getElementById("f-status")?.value || "";
  const minScore = document.getElementById("f-score")?.value  || 0;
  const el       = document.getElementById("incidents-table");
  el.innerHTML   = `<table><tbody>${loadingRow(9)}</tbody></table>`;
  let qs = `?min_score=${minScore}`;
  if (status) qs += `&status=${encodeURIComponent(status)}`;
  try {
    const rows = await apiFetch("/incidents" + qs);
    if (!rows.length) { el.innerHTML = `<table><tbody>${emptyRow(9)}</tbody></table>`; return; }
    let html = `<table><thead><tr>
      <th>#</th><th>Detected</th><th>System</th><th>Attack</th>
      <th>IP</th><th>Score</th><th>Severity</th><th>Status</th><th>Actions</th>
    </tr></thead><tbody>`;
    rows.forEach(r => {
      html += `<tr id="inc-${r.incident_id}">
        <td style="color:var(--muted);font-size:12px;font-weight:800">#${r.incident_id}</td>
        <td style="font-size:12px">${fmtDate(r.detected_at)}</td>
        <td>${r.system_name}</td><td>${r.attack_name}</td>
        <td><span class="ip-chip">${r.attacker_ip}</span></td>
        <td>${scoreBar(r.threat_score)}</td>
        <td><span class="badge ${severityClass(r.severity_level)}">${r.severity_level}</span></td>
        <td><span class="badge ${statusClass(r.status)}">${r.status}</span></td>
        <td><div class="actions">
          <button class="btn-sm" onclick="openEdit(${r.incident_id},'${r.status}',${r.threat_score},\`${(r.description||'').replace(/`/g,"'")}\`)">Edit</button>
          <button class="btn-sm danger" onclick="deleteIncident(${r.incident_id})">Delete</button>
        </div></td>
      </tr>`;
    });
    el.innerHTML = html + "</tbody></table>";
  } catch (e) {
    el.innerHTML = `<table><tbody>${emptyRow(9, "Error: " + e.message)}</tbody></table>`;
    setConnected(false);
  }
}


async function loadAlerts() {
  const el = document.getElementById("alerts-table");
  el.innerHTML = `<table><tbody>${loadingRow(7)}</tbody></table>`;
  try {
    const rows = await apiFetch("/alerts");
    if (!rows.length) {
      el.innerHTML = `<table><tbody>${emptyRow(7, "✓ No unacknowledged critical alerts!")}</tbody></table>`;
      return;
    }
    let html = `<table><thead><tr>
      <th>Alert #</th><th>System</th><th>Attacker IP</th>
      <th>Score</th><th>Message</th><th>Created</th><th>Action</th>
    </tr></thead><tbody>`;
    rows.forEach(r => {
      html += `<tr id="alert-${r.alert_id}">
        <td style="color:var(--muted);font-size:12px;font-weight:800">#${r.alert_id}</td>
        <td>${r.system_name}</td>
        <td><span class="ip-chip">${r.attacker_ip}</span></td>
        <td>${scoreBar(r.threat_score)}</td>
        <td style="font-size:12px;color:var(--muted);max-width:240px">${r.message||"—"}</td>
        <td style="font-size:12px">${fmtDate(r.created_at)}</td>
        <td><button class="btn-sm ack" onclick="ackAlert(${r.alert_id})">✓ Acknowledge</button></td>
      </tr>`;
    });
    el.innerHTML = html + "</tbody></table>";
  } catch (e) {
    el.innerHTML = `<table><tbody>${emptyRow(7, "Error: " + e.message)}</tbody></table>`;
  }
}

async function ackAlert(id) {
  const row = document.getElementById("alert-" + id);
  if (row) row.style.opacity = "0.4";
  try {
    const res = await apiPatch(`/alerts/${id}/acknowledge`, {});
    if (res.success) {
      if (row) row.remove();
      toast("Alert #" + id + " acknowledged ✓", "green");
      loadStats();
    }
  } catch (e) {
    if (row) row.style.opacity = "1";
    toast("Error: " + e.message, "red");
  }
}


async function loadCharts() {
  try {
    const [byType, byDay, byStatus] = await Promise.all([
      apiFetch("/charts/attacks-by-type"),
      apiFetch("/charts/incidents-by-day"),
      apiFetch("/charts/status-breakdown"),
    ]);

    // Purple palette only
    const purpleColors = ["#2e1065","#4c1d95","#5b21b6","#6d28d9","#7c3aed","#8b5cf6","#a78bfa","#c4b5fd"];
    const tickColor = "#6d28d9";
    const gridColor = "rgba(124,58,237,0.10)";
    const legendColor = "#4c1d95";

    // Pie — attacks by type
    if (chartPie) chartPie.destroy();
    chartPie = new Chart(document.getElementById("chart-pie"), {
      type: "doughnut",
      data: {
        labels: byType.map(d => d.attack_name),
        datasets: [{ data: byType.map(d => d.count), backgroundColor: purpleColors, borderWidth: 2, borderColor: "#ffffff" }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: "right", labels: { font: { family: "Poppins", size: 12, weight: "700" }, color: legendColor, padding: 12 } } }
      }
    });

    // Doughnut — status breakdown
    if (chartStatus) chartStatus.destroy();
    const statusColors = { Open: "#2e1065", "In Progress": "#6d28d9", Resolved: "#a78bfa", Closed: "#c4b5fd" };
    chartStatus = new Chart(document.getElementById("chart-status"), {
      type: "doughnut",
      data: {
        labels: byStatus.map(d => d.status),
        datasets: [{ data: byStatus.map(d => d.count), backgroundColor: byStatus.map(d => statusColors[d.status]||"#7c3aed"), borderWidth: 2, borderColor: "#ffffff" }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: "right", labels: { font: { family: "Poppins", size: 12, weight: "700" }, color: legendColor, padding: 12 } } }
      }
    });

    // Bar — incidents by day
    if (chartBar) chartBar.destroy();
    chartBar = new Chart(document.getElementById("chart-bar"), {
      type: "bar",
      data: {
        labels: byDay.map(d => d.day),
        datasets: [{
          label: "Incidents",
          data: byDay.map(d => d.count),
          backgroundColor: "rgba(124,58,237,0.18)",
          borderColor: "#7c3aed",
          borderWidth: 2,
          borderRadius: 6,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: gridColor }, ticks: { font: { family: "Poppins", size: 11, weight: "700" }, color: tickColor } },
          y: { grid: { color: gridColor }, ticks: { font: { family: "Poppins", size: 11, weight: "700" }, color: tickColor, stepSize: 1 }, beginAtZero: true }
        }
      }
    });

  } catch (e) {
    console.error("Chart error:", e);
  }
}


async function loadAttackers() {
  const threshold = document.getElementById("f-threshold")?.value || 1;
  const el = document.getElementById("attackers-table");
  el.innerHTML = `<table><tbody>${loadingRow(6)}</tbody></table>`;
  try {
    const rows = await apiFetch(`/repeat-attackers?threshold=${threshold}`);
    if (!rows.length) { el.innerHTML = `<table><tbody>${emptyRow(6, "No repeat attackers found")}</tbody></table>`; return; }
    let html = `<table><thead><tr>
      <th>IP Address</th><th>Total Attacks</th><th>Attack Types</th>
      <th>Max Score</th><th>Open Incidents</th><th>Last Seen</th>
    </tr></thead><tbody>`;
    rows.forEach(r => {
      html += `<tr>
        <td><span class="ip-chip">${r.attacker_ip}</span></td>
        <td style="font-weight:900;color:#2e1065">${r.total_attacks}</td>
        <td style="font-size:12px;color:var(--muted);font-weight:700">${r.attack_types_used||"—"}</td>
        <td><span style="color:${scoreColor(r.max_threat_score)};font-weight:900">${r.max_threat_score}</span></td>
        <td>${r.open_incidents > 0
          ? `<span class="badge open">${r.open_incidents} open</span>`
          : `<span style="color:var(--muted);font-size:12px;font-weight:700">0</span>`
        }</td>
        <td style="font-size:12px">${fmtDate(r.last_seen)}</td>
      </tr>`;
    });
    el.innerHTML = html + "</tbody></table>";
  } catch (e) {
    el.innerHTML = `<table><tbody>${emptyRow(6, "Error: " + e.message)}</tbody></table>`;
  }
}


async function loadTeams() {
  try {
    const teams = await apiFetch("/teams");
    const sel = document.getElementById("f-team");
    if (!sel) return;
    const cur = sel.value;
    sel.innerHTML = '<option value="">All Teams</option>';
    teams.forEach(t => { sel.innerHTML += `<option value="${t.team_id}">${t.team_name}</option>`; });
    sel.value = cur;
  } catch (e) { /* ignore */ }
}

async function loadReport() {
  const teamId = document.getElementById("f-team")?.value || "";
  const el     = document.getElementById("report-table");
  el.innerHTML = `<table><tbody>${loadingRow(5)}</tbody></table>`;
  let qs = teamId ? `?team_id=${teamId}` : "";
  try {
    const rows = await apiFetch("/response-report" + qs);
    if (!rows.length) { el.innerHTML = `<table><tbody>${emptyRow(5, "No resolved incidents with team assignment found")}</tbody></table>`; return; }
    let html = `<table><thead><tr>
      <th>Team</th><th>Lead</th><th>Total Incidents</th>
      <th>Avg Response Time</th><th>Performance</th>
    </tr></thead><tbody>`;
    rows.forEach(r => {
      // All ratings → purple shades
      const ratingColor = r.performance_rating === "Excellent" ? "#4c1d95"
                        : r.performance_rating === "Good"      ? "#6d28d9"
                        : "#7c3aed";
      const ratingBg    = r.performance_rating === "Excellent" ? "#ede9fe"
                        : r.performance_rating === "Good"      ? "#f5f3ff"
                        : "#faf8ff";
      html += `<tr>
        <td style="font-weight:800">${r.team_name}</td>
        <td style="color:var(--muted);font-weight:700">${r.lead_name||"—"}</td>
        <td style="font-weight:800">${r.total_incidents}</td>
        <td style="font-family:var(--mono);font-size:12px;font-weight:700">${r.avg_response_minutes??"—"} min</td>
        <td><span style="color:${ratingColor};font-weight:900;background:${ratingBg};padding:3px 10px;border-radius:99px;font-size:12px;border:2px solid #c4b5fd">${r.performance_rating}</span></td>
      </tr>`;
    });
    el.innerHTML = html + "</tbody></table>";
  } catch (e) {
    el.innerHTML = `<table><tbody>${emptyRow(5, "Error: " + e.message)}</tbody></table>`;
  }
}


async function loadAuditLog() {
  const el = document.getElementById("audit-table");
  el.innerHTML = `<table><tbody>${loadingRow(5)}</tbody></table>`;
  try {
    const rows = await apiFetch("/audit-log");
    if (!rows.length) { el.innerHTML = `<table><tbody>${emptyRow(5, "No audit records found")}</tbody></table>`; return; }
    let html = `<table><thead><tr>
      <th>#</th><th>User</th><th>Action</th><th>Details</th><th>Time</th>
    </tr></thead><tbody>`;
    rows.forEach(r => {
      // All action colors → purple shades only
      const actionColor = r.action.includes("DELETE") ? "#2e1065"
                        : r.action.includes("LOGIN")  ? "#5b21b6"
                        : r.action.includes("EDIT")   ? "#7c3aed"
                        : "#8b5cf6";
      html += `<tr>
        <td style="color:var(--muted);font-size:12px;font-weight:800">#${r.log_id}</td>
        <td><span class="ip-chip">${r.username}</span></td>
        <td><span style="color:${actionColor};font-size:12px;font-weight:900">${r.action}</span></td>
        <td style="font-size:12px;color:var(--muted);max-width:300px;font-weight:700">${r.details||"—"}</td>
        <td style="font-size:12px">${fmtDate(r.created_at)}</td>
      </tr>`;
    });
    el.innerHTML = html + "</tbody></table>";
  } catch (e) {
    el.innerHTML = `<table><tbody>${emptyRow(5, "Error: " + e.message)}</tbody></table>`;
  }
}


async function openAddModal() {
  document.getElementById("modal-overlay").classList.add("open");
  try {
    const [systems, attacks, teams] = await Promise.all([
      apiFetch("/systems"), apiFetch("/attack-types"), apiFetch("/teams"),
    ]);
    document.getElementById("m-system").innerHTML = systems.map(s => `<option value="${s.system_id}">${s.system_name}</option>`).join("");
    document.getElementById("m-attack").innerHTML = attacks.map(a => `<option value="${a.attack_type_id}">${a.attack_name} (${a.severity_level})</option>`).join("");
    document.getElementById("m-team").innerHTML  = '<option value="">Unassigned</option>' +
      teams.map(t => `<option value="${t.team_id}">${t.team_name}</option>`).join("");
  } catch (e) { /* default */ }
}

function closeModal() {
  document.getElementById("modal-overlay").classList.remove("open");
  document.getElementById("m-msg").className = "form-msg";
}

async function submitIncident() {
  const ip    = document.getElementById("m-ip").value.trim();
  const score = parseInt(document.getElementById("m-score").value);
  const desc  = document.getElementById("m-desc").value.trim();
  const msg   = document.getElementById("m-msg");

  if (!ip)   { msg.className = "form-msg error"; msg.textContent = "Attacker IP is required."; return; }
  if (!desc) { msg.className = "form-msg error"; msg.textContent = "Description is required."; return; }
  if (isNaN(score)||score<0||score>100) { msg.className = "form-msg error"; msg.textContent = "Threat score must be 0–100."; return; }

  msg.className = "form-msg";
  const body = {
    system_id:      parseInt(document.getElementById("m-system").value),
    attack_type_id: parseInt(document.getElementById("m-attack").value),
    attacker_ip:    ip, threat_score: score,
    status:         document.getElementById("m-status").value,
    description:    desc,
  };
  const teamVal = document.getElementById("m-team").value;
  if (teamVal) body.team_id = parseInt(teamVal);

  try {
    const res = await apiPost("/incidents", body);
    if (res.success) {
      closeModal();
      const alertNote = res.alert_triggered ? " ⚠ Critical alert auto-created!" : "";
      toast(`Incident #${res.incident_id} added.${alertNote}`, "green");
      loadStats();
      if (currentPage === "incidents") loadIncidents();
      if (currentPage === "dashboard") loadDashboard();
    } else {
      msg.className = "form-msg error"; msg.textContent = res.error || "Failed to add incident.";
    }
  } catch (e) {
    msg.className = "form-msg error"; msg.textContent = "Network error: " + e.message;
  }
}


function openEdit(id, status, score, desc) {
  document.getElementById("e-id").value     = id;
  document.getElementById("e-status").value = status;
  document.getElementById("e-score").value  = score;
  document.getElementById("e-desc").value   = desc;
  document.getElementById("edit-title").textContent = `Edit Incident #${id}`;
  document.getElementById("edit-overlay").classList.add("open");
}

function closeEdit() { document.getElementById("edit-overlay").classList.remove("open"); }

async function saveEdit() {
  const id    = document.getElementById("e-id").value;
  const status= document.getElementById("e-status").value;
  const score = parseInt(document.getElementById("e-score").value);
  const desc  = document.getElementById("e-desc").value.trim();
  const msg   = document.getElementById("e-msg");

  if (isNaN(score)||score<0||score>100) { msg.className="form-msg error"; msg.textContent="Score must be 0–100."; return; }
  let body = { status, threat_score: score, description: desc };
  if (status === "Resolved") body.resolved_at = new Date().toISOString().slice(0,19).replace("T"," ");

  try {
    const res = await apiPatch(`/incidents/${id}`, body);
    if (res.success) {
      closeEdit();
      toast(`Incident #${id} updated.`, "green");
      loadStats();
      if (currentPage === "incidents") loadIncidents();
      if (currentPage === "dashboard") loadDashboard();
    } else { msg.className="form-msg error"; msg.textContent=res.error||"Update failed."; }
  } catch (e) { msg.className="form-msg error"; msg.textContent="Error: "+e.message; }
}


async function deleteIncident(id) {
  if (!confirm(`Delete incident #${id}? This cannot be undone.`)) return;
  try {
    const res = await apiDelete(`/incidents/${id}`);
    if (res.success) {
      const row = document.getElementById("inc-" + id);
      if (row) row.remove();
      toast(`Incident #${id} deleted.`, "green");
      loadStats();
    } else { toast("Delete failed: " + res.error, "red"); }
  } catch (e) { toast("Error: " + e.message, "red"); }
}


let toastTimer;
function toast(msg, type = "") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className   = "toast show " + type;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = "toast"; }, 3500);
}


async function loadUser() {
  try {
    const res  = await fetch("/api/me");
    const data = await res.json();
    if (data.success) {
      document.getElementById("user-pill").textContent = `👤 ${data.user} (${data.role})`;
    }
  } catch (e) { /* ignore */ }
}


document.addEventListener("DOMContentLoaded", () => {
  loadUser();
  navigate("dashboard");
});