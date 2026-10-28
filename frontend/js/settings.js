/**
 * NPM Shield AI - Settings & System Info Module
 */

async function loadSettingsView() {
  try {
    const data = await API.getSettings();
    document.getElementById("setBackendStatus").textContent = data.backend_status || "Connected & Operational";
    document.getElementById("setDbStatus").textContent = data.database || "Local SQLite (npm_shield.db)";
    document.getElementById("setAiStatus").textContent = data.ai_provider || "Deterministic Expert Security Engine";
  } catch (err) {
    console.error("Failed to load settings:", err);
    document.getElementById("setBackendStatus").textContent = "Connection Error";
  }
}
