/**
 * NPM Shield AI - Centralized Fetch API Client
 */

const API_BASE = "/api";

async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  try {
    const resp = await fetch(url, options);
    if (!resp.ok) {
      let errorMsg = `HTTP Error ${resp.status}`;
      try {
        const errorData = await resp.json();
        if (errorData.detail) errorMsg = errorData.detail;
      } catch (e) {}
      throw new Error(errorMsg);
    }
    return await resp.json();
  } catch (err) {
    console.error(`API Request failed for ${url}:`, err);
    throw err;
  }
}

const API = {
  getOverview: () => apiRequest("/overview"),
  
  scanPackage: (packageName, version = null, isDemo = false) => {
    return apiRequest("/scans/package", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package_name: packageName, version: version, is_demo: isDemo })
    });
  },

  scanProject: (formData) => {
    return apiRequest("/scans/project", {
      method: "POST",
      body: formData
    });
  },

  getScans: (search = "", severity = "all", sortBy = "created_at", sortOrder = "desc") => {
    const params = new URLSearchParams();
    if (search) params.append("search", search);
    if (severity && severity !== "all") params.append("severity", severity);
    params.append("sort_by", sortBy);
    params.append("sort_order", sortOrder);
    return apiRequest(`/scans?${params.toString()}`);
  },

  getScan: (scanId) => apiRequest(`/scans/${scanId}`),

  getScanReport: (scanId) => apiRequest(`/scans/${scanId}/report`),

  rescan: (scanId) => apiRequest(`/scans/${scanId}/rescan`, { method: "POST" }),

  deleteScan: (scanId) => apiRequest(`/scans/${scanId}`, { method: "DELETE" }),

  getDependencies: (scanId) => apiRequest(`/scans/${scanId}/dependencies`),

  getHealth: () => apiRequest("/health"),

  getSettings: () => apiRequest("/settings")
};
