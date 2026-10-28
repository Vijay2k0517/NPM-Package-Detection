/**
 * NPM Shield AI - Frontend Utility Functions
 */

function escapeHtml(text) {
  if (text === null || text === undefined) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatDate(dateStr) {
  if (!dateStr) return "N/A";
  try {
    const d = new Date(dateStr);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    });
  } catch (e) {
    return dateStr;
  }
}

function getSeverityBadge(severity) {
  const s = (severity || "low").toLowerCase();
  if (s === "critical") {
    return `<span class="badge badge-critical">CRITICAL</span>`;
  } else if (s === "high") {
    return `<span class="badge badge-high">HIGH</span>`;
  } else if (s === "medium") {
    return `<span class="badge badge-medium">MEDIUM</span>`;
  } else {
    return `<span class="badge badge-low">LOW</span>`;
  }
}

function renderRiskGauge(score, circleEl, textEl, badgeEl) {
  const safeScore = Math.min(100, Math.max(0, parseFloat(score) || 0));
  if (textEl) {
    textEl.textContent = safeScore.toFixed(0);
  }

  // Radial calculation (r=40 -> circumference ~251.2)
  const maxDash = 251.2;
  const offset = maxDash - (safeScore / 100) * maxDash;

  let strokeColor = "#15803D"; // Low
  let badgeHtml = `<span class="badge badge-low">LOW RISK</span>`;

  if (safeScore >= 80) {
    strokeColor = "#991B1B";
    badgeHtml = `<span class="badge badge-critical">CRITICAL RISK</span>`;
  } else if (safeScore >= 70) {
    strokeColor = "#DC2626";
    badgeHtml = `<span class="badge badge-high">HIGH RISK</span>`;
  } else if (safeScore >= 30) {
    strokeColor = "#D97706";
    badgeHtml = `<span class="badge badge-medium">MEDIUM RISK</span>`;
  }

  if (circleEl) {
    circleEl.style.strokeDashoffset = offset;
    circleEl.style.stroke = strokeColor;
  }
  if (badgeEl) {
    badgeEl.innerHTML = badgeHtml;
  }
}
