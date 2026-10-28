/**
 * NPM Shield AI - Security Overview Dashboard Module
 */

async function loadDashboardOverview() {
  try {
    const data = await API.getOverview();

    // Stats Counters
    document.getElementById("statTotalScanned").textContent = data.total_scanned || 0;
    document.getElementById("statHighRisk").textContent = data.high_risk_count || 0;
    document.getElementById("statTotalVulns").textContent = data.total_vulnerabilities_found || 0;
    document.getElementById("statCleanCount").textContent = data.clean_count || 0;

    // Risk Distribution Bar Chart
    renderRiskDistribution(data.risk_distribution, data.total_scanned);

    // Recent Scans Table
    renderOverviewTable(data.recent_scans);
  } catch (err) {
    console.error("Failed to load dashboard overview:", err);
  }
}

function renderRiskDistribution(dist, total) {
  const container = document.getElementById("riskDistributionContainer");
  const card = document.getElementById("riskDistCard");

  if (!total || total === 0) {
    card.style.display = "none";
    return;
  }

  card.style.display = "block";
  container.innerHTML = "";

  const categories = [
    { key: "critical", label: "Critical", color: "var(--severity-critical)", count: dist.critical || 0 },
    { key: "high", label: "High", color: "var(--severity-high)", count: dist.high || 0 },
    { key: "medium", label: "Medium", color: "var(--severity-medium)", count: dist.medium || 0 },
    { key: "low", label: "Low / Clean", color: "var(--severity-low)", count: dist.low || 0 }
  ];

  const maxCount = Math.max(...categories.map(c => c.count), 1);

  categories.forEach(cat => {
    const heightPercent = Math.max(12, (cat.count / maxCount) * 80);
    const col = document.createElement("div");
    col.style = "flex: 1; display: flex; flex-direction: column; align-items: center; gap: 6px;";

    col.innerHTML = `
      <div style="font-size: 13px; font-weight: 700; color: ${cat.color};">${cat.count}</div>
      <div style="width: 100%; height: ${heightPercent}px; background-color: ${cat.color}; border-radius: var(--radius-xs); opacity: 0.85;"></div>
      <div style="font-size: 11px; color: var(--text-secondary); text-align: center;">${cat.label}</div>
    `;
    container.appendChild(col);
  });
}

function renderOverviewTable(scans) {
  const tbody = document.getElementById("overviewScansTableBody");
  tbody.innerHTML = "";

  if (!scans || scans.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8">
          <div class="empty-state">
            <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            <div class="empty-state-title">No Scans Recorded</div>
            <div class="empty-state-desc">You have not analyzed any packages yet. Start your first security audit above.</div>
            <button class="btn btn-primary btn-sm" onclick="navigateTo('scanner')">Scan a Package</button>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  scans.forEach(s => {
    const tr = document.createElement("tr");
    const badge = getSeverityBadge(s.risk_level);
    const dateFormatted = formatDate(s.created_at);

    tr.innerHTML = `
      <td style="font-weight: 600;">
        <a href="javascript:void(0)" onclick="viewReport('${escapeHtml(s.id)}')">${escapeHtml(s.package_name)}</a>
        ${s.is_demo ? '<span class="badge" style="background:#E0E7FF; color:#3730A3; font-size:10px; margin-left:4px;">DEMO</span>' : ''}
      </td>
      <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary);">${escapeHtml(s.version || 'latest')}</td>
      <td><span style="text-transform: capitalize; font-size: 12px;">${escapeHtml(s.scan_type)}</span></td>
      <td style="font-weight: 700;">${(s.risk_score || 0).toFixed(0)} / 100</td>
      <td>${badge}</td>
      <td>${s.total_findings || 0}</td>
      <td style="color: var(--text-secondary); font-size: 12px;">${dateFormatted}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="viewReport('${escapeHtml(s.id)}')">View Report</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}
