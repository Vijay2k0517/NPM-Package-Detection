/**
 * NPM Shield AI - Scan History Module
 */

let allHistoryScans = [];

async function loadScanHistory() {
  const search = document.getElementById("historySearchInput").value.trim();
  const severity = document.getElementById("historySeverityFilter").value;

  try {
    const scans = await API.getScans(search, severity, "created_at", "desc");
    allHistoryScans = scans || [];
    renderHistoryTable(allHistoryScans);
  } catch (err) {
    console.error("Failed to load scan history:", err);
  }
}

function handleHistoryFilter() {
  loadScanHistory();
}

function renderHistoryTable(scans) {
  const tbody = document.getElementById("historyTableBody");
  tbody.innerHTML = "";

  if (!scans || scans.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8">
          <div class="empty-state">
            <div class="empty-state-title">No Scan Records Found</div>
            <div class="empty-state-desc">Try clearing your search filters or start a new scan.</div>
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
      <td><strong>${s.total_findings || 0}</strong></td>
      <td style="color: var(--text-secondary); font-size: 12px;">${dateFormatted}</td>
      <td>
        <div style="display: flex; gap: 6px;">
          <button class="btn btn-secondary btn-sm" onclick="viewReport('${escapeHtml(s.id)}')">View</button>
          <button class="btn btn-secondary btn-sm" onclick="rescanFromHistory('${escapeHtml(s.id)}')">Rescan</button>
          <button class="btn btn-secondary btn-sm" style="color: var(--severity-high);" onclick="deleteScanFromHistory('${escapeHtml(s.id)}')">Delete</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function viewReport(scanId) {
  window.currentScanId = scanId;
  loadReport(scanId);
  navigateTo("report");
}

async function rescanFromHistory(scanId) {
  try {
    const newScan = await API.rescan(scanId);
    await loadScanHistory();
    viewReport(newScan.id);
  } catch (err) {
    alert(`Rescan failed: ${err.message}`);
  }
}

async function deleteScanFromHistory(scanId) {
  if (!confirm("Are you sure you want to delete this scan record?")) return;
  try {
    await API.deleteScan(scanId);
    await loadScanHistory();
    await loadDashboardOverview();
  } catch (err) {
    alert(`Delete failed: ${err.message}`);
  }
}
