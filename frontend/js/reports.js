/**
 * NPM Shield AI - Reports & Export Module
 */

async function loadReportsExportView() {
  const select = document.getElementById("exportScanSelect");
  select.innerHTML = "<option value=''>Loading scan records...</option>";

  try {
    const scans = await API.getScans("", "all", "created_at", "desc");
    select.innerHTML = "";

    if (!scans || scans.length === 0) {
      select.innerHTML = "<option value=''>No scans available</option>";
      return;
    }

    scans.forEach(s => {
      const opt = document.createElement("option");
      opt.value = s.id;
      opt.textContent = `${s.package_name}@${s.version || 'latest'} (Score: ${(s.risk_score || 0).toFixed(0)}, ${formatDate(s.created_at)})`;
      select.appendChild(opt);
    });

    if (window.currentScanId) {
      select.value = window.currentScanId;
    }
  } catch (err) {
    console.error("Failed to load export scans:", err);
  }
}

function exportSelectedScan(format) {
  const select = document.getElementById("exportScanSelect");
  const scanId = select.value;
  if (!scanId) {
    alert("Please select a scan to export.");
    return;
  }
  window.open(`/api/scans/${scanId}/export?format=${format}`, "_blank");
}
