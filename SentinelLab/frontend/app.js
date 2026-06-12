const API = "http://localhost:8000";

const fallback = {
  summary: {
    total_events: 18,
    total_alerts: 4,
    critical_alerts: 1,
    high_alerts: 2,
    assets: 5,
    top_sources: [{ ip: "203.0.113.44", events: 7 }],
    alerts_by_severity: { critical: 1, high: 2, medium: 1 },
    alerts_by_tactic: { "Credential Access": 1, Discovery: 1, Execution: 1, Command: 1 },
  },
  alerts: [
    {
      id: "AL-DEMO001",
      title: "Possible brute force against VPN",
      severity: "critical",
      tactic: "Credential Access",
      entity: "203.0.113.44 | m.costa",
      evidence_count: 6,
      description: "Multiple failed authentication attempts occurred in a short time window.",
      tags: ["vpn", "identity"],
      evidence: [],
    },
    {
      id: "AL-DEMO002",
      title: "Suspicious PowerShell execution",
      severity: "high",
      tactic: "Execution",
      entity: "FIN-WS-04",
      evidence_count: 1,
      description: "Command line contained encoded or download-oriented PowerShell behavior.",
      tags: ["endpoint", "powershell"],
      evidence: [],
    },
  ],
  events: [
    { timestamp: "2026-06-12T10:04:00Z", event_type: "auth", src_ip: "203.0.113.44", username: "m.costa", hostname: "vpn-01", status: "failure" },
    { timestamp: "2026-06-12T10:13:00Z", event_type: "process", src_ip: "10.20.5.24", username: "svc-finance", hostname: "FIN-WS-04", process: "powershell.exe" },
  ],
  rules: [],
};

const state = {
  summary: fallback.summary,
  alerts: fallback.alerts,
  events: fallback.events,
  rules: fallback.rules,
  online: false,
};

document.addEventListener("DOMContentLoaded", () => {
  bindNavigation();
  bindActions();
  refreshData();
});

function bindNavigation() {
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach((item) => item.classList.remove("active"));
      document.querySelectorAll(".view").forEach((view) => view.classList.remove("active"));
      button.classList.add("active");
      document.getElementById(button.dataset.view).classList.add("active");
    });
  });
}

function bindActions() {
  document.getElementById("refreshBtn").addEventListener("click", refreshData);
  document.getElementById("reportBtn").addEventListener("click", createReport);
  document.getElementById("severityFilter").addEventListener("change", renderInvestigations);
  document.getElementById("fileInput").addEventListener("change", analyzeFile);
}

async function refreshData() {
  try {
    const [summary, alerts, events, rules] = await Promise.all([
      getJson("/summary"),
      getJson("/alerts"),
      getJson("/events"),
      getJson("/rules"),
    ]);
    Object.assign(state, { summary, alerts, events, rules, online: true });
    showToast("API connected. SOC data refreshed.");
  } catch (error) {
    state.online = false;
    showToast("Using embedded demo data. Start the API for live endpoints.");
  }
  renderAll();
}

async function getJson(path) {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`Request failed: ${path}`);
  return response.json();
}

function renderAll() {
  renderStatus();
  renderMetrics();
  renderAlerts();
  renderTimeline();
  renderInvestigations();
  renderRules();
}

function renderStatus() {
  document.getElementById("apiStatus").textContent = state.online ? "API online" : "Demo mode";
  document.querySelector(".status-dot").classList.toggle("online", state.online);
}

function renderMetrics() {
  const metrics = [
    ["Events", state.summary.total_events],
    ["Open alerts", state.summary.total_alerts],
    ["Critical", state.summary.critical_alerts],
    ["High", state.summary.high_alerts],
    ["Assets", state.summary.assets],
  ];
  document.getElementById("metricsGrid").innerHTML = metrics
    .map(([label, value]) => `<article class="metric"><span>${label}</span><strong>${value}</strong></article>`)
    .join("");
}

function renderAlerts() {
  document.getElementById("alertCount").textContent = `${state.alerts.length} open`;
  document.getElementById("alertList").innerHTML = state.alerts
    .slice(0, 6)
    .map(
      (alert) => `
      <article class="alert-card">
        <div class="alert-top">
          <span class="badge ${alert.severity}">${alert.severity}</span>
          <strong>${alert.title}</strong>
          <span>${alert.tactic}</span>
          <span>${alert.evidence_count} events</span>
        </div>
        <p>${alert.description}</p>
        <p>Entity: ${alert.entity}</p>
      </article>`
    )
    .join("");
}

function renderTimeline() {
  document.getElementById("timeline").innerHTML = state.events
    .slice()
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 8)
    .map(
      (event) => `
      <article class="timeline-item">
        <strong>${event.event_type} on ${event.hostname || event.src_ip || event.source_ip}</strong>
        <p>${new Date(event.timestamp).toLocaleString()} - ${event.username || "system"} - ${event.status || event.action || event.process || "observed"}</p>
      </article>`
    )
    .join("");
}

function renderInvestigations() {
  const selected = document.getElementById("severityFilter").value;
  const alerts = selected === "all" ? state.alerts : state.alerts.filter((alert) => alert.severity === selected);
  document.getElementById("investigationTable").innerHTML = alerts
    .map(
      (alert) => `
      <div class="table-row">
        <span class="badge ${alert.severity}">${alert.severity}</span>
        <div><strong>${alert.title}</strong><span>${alert.description}</span></div>
        <span>${alert.entity}</span>
        <span>${alert.tactic}</span>
      </div>`
    )
    .join("");
}

function renderRules() {
  const rules = state.rules.length ? state.rules : [
    { id: "SL-DEMO", name: "Demo rules load from API", severity: "medium", tactic: "Configuration", description: "Start the FastAPI backend to inspect YAML detections.", tags: ["demo"] },
  ];
  document.getElementById("rulesList").innerHTML = rules
    .map(
      (rule) => `
      <article class="rule-card">
        <span class="badge ${rule.severity}">${rule.severity}</span>
        <h2>${rule.name}</h2>
        <p>${rule.description}</p>
        <p>${rule.id} - ${rule.tactic} - ${(rule.tags || []).join(", ")}</p>
      </article>`
    )
    .join("");
}

async function analyzeFile(event) {
  const file = event.target.files[0];
  if (!file) return;

  const result = document.getElementById("fileResult");
  result.classList.add("active");
  result.textContent = "Analyzing file...";

  if (!state.online) {
    result.innerHTML = `<strong>${file.name}</strong><p>Start the API to run live file triage. The frontend is ready to POST to /analyze-file.</p>`;
    return;
  }

  const form = new FormData();
  form.append("file", file);
  const response = await fetch(`${API}/analyze-file`, { method: "POST", body: form });
  const analysis = await response.json();
  result.innerHTML = `
    <strong>${analysis.filename}</strong>
    <p>SHA256: ${analysis.sha256}</p>
    <p>Entropy: ${analysis.entropy} | Risk: ${analysis.risk_score}/100 | ${analysis.classification}</p>
    <p>${analysis.findings.map((finding) => `${finding.severity.toUpperCase()}: ${finding.detail}`).join("\n") || "No suspicious findings."}</p>
  `;
}

async function createReport() {
  if (!state.online) {
    showToast("Start the API to generate a Markdown report in /reports.");
    return;
  }
  const response = await fetch(`${API}/reports`, { method: "POST" });
  const payload = await response.json();
  showToast(`Report generated: ${payload.path}`);
}

function showToast(message) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.classList.add("active");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("active"), 3500);
}

