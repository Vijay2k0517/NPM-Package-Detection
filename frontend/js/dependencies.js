/**
 * NPM Shield AI - Dependency Analysis & Interactive Graph Module
 */

let allCurrentDependencies = [];

async function loadDependenciesView() {
  if (!window.currentScanId) {
    const recent = await API.getScans("", "all", "created_at", "desc");
    if (recent && recent.length > 0) {
      window.currentScanId = recent[0].id;
    }
  }

  if (!window.currentScanId) {
    renderEmptyDependenciesState();
    return;
  }

  try {
    const deps = await API.getDependencies(window.currentScanId);
    allCurrentDependencies = deps || [];
    renderDependenciesTable(allCurrentDependencies);
    renderSvgDependencyGraph(allCurrentDependencies);
  } catch (err) {
    console.error("Failed to load dependencies:", err);
  }
}

function renderDependenciesTable(deps) {
  const tbody = document.getElementById("dependenciesTableBody");
  tbody.innerHTML = "";

  if (!deps || deps.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 32px;">
          No dependency tree data available for this scan. Run a project manifest audit (package.json / package-lock.json).
        </td>
      </tr>
    `;
    return;
  }

  deps.forEach(d => {
    const tr = document.createElement("tr");
    const badge = getSeverityBadge(d.risk_level);

    tr.innerHTML = `
      <td style="font-weight: 600;">${escapeHtml(d.name)}</td>
      <td style="font-family: var(--font-mono); font-size: 12px;">${escapeHtml(d.version)}</td>
      <td><span class="badge" style="background: var(--bg-surface-subtle); color: var(--text-secondary);">${escapeHtml(d.dep_type)}</span></td>
      <td>${escapeHtml(d.parent_name || 'root')}</td>
      <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">${escapeHtml(d.dependency_path || d.name)}</td>
      <td>${badge}</td>
      <td><strong>${d.findings_count || 0}</strong></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderSvgDependencyGraph(deps) {
  const svg = document.getElementById("dependencySvgGraph");
  svg.innerHTML = "";

  if (!deps || deps.length === 0) {
    svg.innerHTML = `
      <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" fill="#98A2B3" font-size="14">
        No dependency hierarchy to visualize. Upload a package.json to generate graph.
      </text>
    `;
    return;
  }

  // Generate lightweight SVG layout
  const width = svg.clientWidth || 800;
  const height = svg.clientHeight || 450;
  
  const rootX = 100;
  const rootY = height / 2;

  // Root Node
  let svgContent = `
    <defs>
      <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.1"/>
      </filter>
    </defs>
    <!-- Root Center Node -->
    <g class="graph-node" transform="translate(${rootX}, ${rootY})">
      <circle r="36" fill="#5145CD" filter="url(#shadow)"/>
      <text text-anchor="middle" dy="4" fill="#FFFFFF" font-size="11" font-weight="600">PROJECT</text>
    </g>
  `;

  // Place dependencies in radial / column arcs
  const displayDeps = deps.slice(0, 16); // up to 16 nodes for clean rendering
  const total = displayDeps.length;
  const colX = 340;
  const stepY = height / (total + 1);

  displayDeps.forEach((dep, idx) => {
    const nodeY = (idx + 1) * stepY;
    const isRisky = dep.risk_level === "critical" || dep.risk_level === "high";
    const nodeColor = isRisky ? "#DC2626" : (dep.risk_level === "medium" ? "#D97706" : "#15803D");
    const nodeBg = isRisky ? "#FEF2F2" : "#FFFFFF";

    // Connecting line
    svgContent += `
      <path d="M ${rootX + 36} ${rootY} C ${(rootX + colX) / 2} ${rootY}, ${(rootX + colX) / 2} ${nodeY}, ${colX - 120} ${nodeY}" 
            fill="none" stroke="#D0D5DD" stroke-width="1.5" stroke-dasharray="${dep.dep_type === 'dev' ? '4,4' : 'none'}"/>
      <!-- Node Box -->
      <g transform="translate(${colX - 120}, ${nodeY - 18})" style="cursor: pointer;" onclick="alert('Dependency: ${escapeHtml(dep.name)}@${escapeHtml(dep.version)}\\nPath: ${escapeHtml(dep.dependency_path || dep.name)}\\nRisk: ${dep.risk_level.toUpperCase()}')">
        <rect width="260" height="36" rx="6" fill="${nodeBg}" stroke="${nodeColor}" stroke-width="${isRisky ? 2 : 1}" filter="url(#shadow)"/>
        <circle cx="16" cy="18" r="5" fill="${nodeColor}"/>
        <text x="30" y="22" fill="#202733" font-size="12" font-weight="600">${escapeHtml(dep.name.substring(0, 24))}</text>
        <text x="210" y="22" fill="#667085" font-size="11" font-family="monospace">${escapeHtml(dep.version)}</text>
      </g>
    `;
  });

  svg.innerHTML = svgContent;
}

function renderEmptyDependenciesState() {
  document.getElementById("dependenciesTableBody").innerHTML = `
    <tr>
      <td colspan="7">
        <div class="empty-state">
          <div class="empty-state-title">No Dependencies Loaded</div>
          <div class="empty-state-desc">Run a project dependency scan from the Package Scanner to populate the dependency analysis table.</div>
          <button class="btn btn-primary btn-sm" onclick="navigateTo('scanner')">Go to Scanner</button>
        </div>
      </td>
    </tr>
  `;
}
