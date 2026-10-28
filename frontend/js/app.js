/**
 * NPM Shield AI - Main Application Router & Controller
 */

function navigateTo(viewId) {
  // Update nav links
  const links = document.querySelectorAll("#mainNav .nav-link");
  links.forEach(link => {
    link.classList.toggle("active", link.dataset.view === viewId);
  });

  // Update view sections
  const sections = document.querySelectorAll(".view-section");
  sections.forEach(sec => {
    sec.classList.toggle("active", sec.id === `view-${viewId}`);
  });

  // Set window hash without full reload
  window.location.hash = viewId;

  // Trigger view data loaders
  if (viewId === "overview") {
    loadDashboardOverview();
  } else if (viewId === "report") {
    loadReport(window.currentScanId);
  } else if (viewId === "dependencies") {
    loadDependenciesView();
  } else if (viewId === "history") {
    loadScanHistory();
  } else if (viewId === "reports") {
    loadReportsExportView();
  } else if (viewId === "settings") {
    loadSettingsView();
  }
}

// Initial Startup
document.addEventListener("DOMContentLoaded", async () => {
  // Health check
  try {
    const health = await API.getHealth();
    document.getElementById("topStatusDot").style.backgroundColor = "var(--severity-low)";
    document.getElementById("topStatusText").textContent = "Backend Connected";
  } catch (e) {
    document.getElementById("topStatusDot").style.backgroundColor = "var(--severity-high)";
    document.getElementById("topStatusText").textContent = "Backend Offline";
  }

  // Handle hash routing
  const hash = window.location.hash.replace("#", "");
  const validViews = ["overview", "scanner", "report", "dependencies", "history", "reports", "settings"];
  
  if (validViews.includes(hash)) {
    navigateTo(hash);
  } else {
    navigateTo("overview");
  }
});

window.addEventListener("hashchange", () => {
  const hash = window.location.hash.replace("#", "");
  if (hash) navigateTo(hash);
});
