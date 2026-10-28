/**
 * NPM Shield AI - Security Analysis Report Module
 */

let currentReportData = null;

async function loadReport(scanId) {
  if (!scanId) {
    // If no scan selected, show empty state or load latest
    const recent = await API.getScans("", "all", "created_at", "desc");
    if (recent && recent.length > 0) {
      scanId = recent[0].id;
    } else {
      renderEmptyReportState();
      return;
    }
  }

  window.currentScanId = scanId;

  try {
    const data = await API.getScan(scanId);
    currentReportData = data;
    renderReportView(data);
  } catch (err) {
    console.error("Failed to load scan report:", err);
    alert(`Could not load report: ${err.message}`);
  }
}

function renderReportView(data) {
  document.getElementById("repPkgHeader").textContent = `${data.package_name}`;
  document.getElementById("repMetaSub").textContent = `Inspection report for version ${data.version || 'latest'} • ${data.scan_type.toUpperCase()} scan`;
  
  document.getElementById("repPkgName").textContent = data.package_name;
  document.getElementById("repPkgVersion").textContent = `v${data.version || 'latest'}`;
  document.getElementById("repScanTimestamp").textContent = `Scanned ${formatDate(data.created_at)}`;
  document.getElementById("repSummaryText").textContent = data.summary || "Security evaluation completed.";

  // Score Dial Gauge
  renderRiskGauge(
    data.risk_score || 0,
    document.getElementById("repGaugeCircle"),
    document.getElementById("repScoreText"),
    document.getElementById("repSeverityBadge")
  );

  // Counters
  document.getElementById("badgeCritCount").textContent = `${data.critical_count || 0} Critical`;
  document.getElementById("badgeHighCount").textContent = `${data.high_count || 0} High`;
  document.getElementById("badgeMedCount").textContent = `${data.medium_count || 0} Medium`;
  document.getElementById("badgeLowCount").textContent = `${data.low_count || 0} Low`;
  document.getElementById("badgeTotalFindings").textContent = `${data.total_findings || 0} Total Findings`;

  // AI Explanation Section
  document.getElementById("repAiExplanationText").textContent = data.ai_explanation || "No explanation recorded.";
  document.getElementById("repAiProviderLabel").textContent = `Engine: ${data.ai_provider || 'Deterministic Security Engine'}`;

  // Recommendations
  const recsList = document.getElementById("repRecommendationsList");
  recsList.innerHTML = "";
  if (data.recommendations && data.recommendations.length > 0) {
    data.recommendations.forEach(rec => {
      const li = document.createElement("li");
      li.textContent = rec;
      recsList.appendChild(li);
    });
  } else {
    recsList.innerHTML = "<li>No specific actions required. Maintain standard dependency monitoring.</li>";
  }

  // Findings List
  renderFindings(data.findings || []);
}

function renderFindings(findings) {
  const container = document.getElementById("findingsContainer");
  container.innerHTML = "";

  if (!findings || findings.length === 0) {
    container.innerHTML = `
      <div class="empty-state" style="padding: 32px;">
        <svg class="empty-state-icon" style="color: var(--severity-low);" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="m9 12 2 2 4-4"/>
        </svg>
        <div class="empty-state-title" style="color: var(--severity-low);">Zero Suspicious Indicators</div>
        <div class="empty-state-desc">Static heuristics, AST inspection, and OSV vulnerability advisories did not identify suspicious patterns.</div>
      </div>
    `;
    return;
  }

  findings.forEach((f, idx) => {
    const item = document.createElement("div");
    item.className = "finding-item";
    if (idx === 0) item.classList.add("open"); // open first finding by default

    const sevBadge = getSeverityBadge(f.severity);
    const sourceLabel = f.source ? f.source.replace("_", " ").toUpperCase() : "HEURISTIC";
    const loc = f.file_path ? `${escapeHtml(f.file_path)}${f.line_number ? ':' + f.line_number : ''}` : "Package Root";

    let codeHtml = "";
    if (f.code_snippet) {
      codeHtml = `
        <div style="font-weight: 600; font-size: 12px; margin-top: 10px;">Observed Code Snippet / Pattern:</div>
        <pre class="code-block">${escapeHtml(f.code_snippet)}</pre>
      `;
    }

    let refHtml = "";
    if (f.references && f.references.length > 0) {
      refHtml = `
        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 8px;">
          <strong>References:</strong> ${f.references.map(r => `<a href="${escapeHtml(r)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r)}</a>`).join(", ")}
        </div>
      `;
    }

    item.innerHTML = `
      <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
        <div class="finding-title-group">
          ${sevBadge}
          <span style="font-weight: 600; font-size: 14px;">${escapeHtml(f.title)}</span>
          <span style="font-size: 11px; background: var(--bg-surface-subtle); border: 1px solid var(--border-color); padding: 2px 6px; border-radius: 4px; color: var(--text-secondary);">${sourceLabel}</span>
        </div>
        <div style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary);">
          ${loc} ▾
        </div>
      </div>
      <div class="finding-body">
        <p style="margin-bottom: 8px;">${escapeHtml(f.description)}</p>
        ${codeHtml}
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 12px; background: var(--bg-surface); padding: 12px; border-radius: var(--radius-xs); border: 1px solid var(--border-color);">
          <div>
            <strong>Potential Impact:</strong>
            <p style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(f.impact || 'Potential unauthorized system interaction.')}</p>
          </div>
          <div>
            <strong>Recommended Action:</strong>
            <p style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(f.recommendation || 'Inspect source code.')}</p>
          </div>
        </div>
        ${refHtml}
      </div>
    `;

    container.appendChild(item);
  });
}

function renderEmptyReportState() {
  document.getElementById("repPkgHeader").textContent = "No Report Selected";
  document.getElementById("repMetaSub").textContent = "Run a scan or pick an existing record from history.";
  document.getElementById("findingsContainer").innerHTML = `
    <div class="empty-state">
      <div class="empty-state-title">No Scan Selected</div>
      <div class="empty-state-desc">Select an entry from your Scan History or run a new scan from the Package Scanner.</div>
      <button class="btn btn-primary btn-sm" onclick="navigateTo('scanner')">Go to Scanner</button>
    </div>
  `;
}

async function rescanCurrentReport() {
  if (!window.currentScanId) return;
  try {
    const newScan = await API.rescan(window.currentScanId);
    await loadReport(newScan.id);
  } catch (err) {
    alert(`Rescan failed: ${err.message}`);
  }
}

function downloadCurrentJson() {
  if (!window.currentScanId) return;
  window.open(`/api/scans/${window.currentScanId}/export?format=json`, "_blank");
}

function downloadCurrentCsv() {
  if (!window.currentScanId) return;
  window.open(`/api/scans/${window.currentScanId}/export?format=csv`, "_blank");
}
