/**
 * NPM Shield AI - Package Scanner Module
 */

let selectedManifestFile = null;

function setScanMode(mode) {
  const singleCard = document.getElementById("singleScanCard");
  const projectCard = document.getElementById("projectScanCard");
  const btnSingle = document.getElementById("btnSingleMode");
  const btnProject = document.getElementById("btnProjectMode");

  if (mode === "single") {
    singleCard.style.display = "block";
    projectCard.style.display = "none";
    btnSingle.className = "btn btn-primary btn-sm";
    btnProject.className = "btn btn-secondary btn-sm";
  } else {
    singleCard.style.display = "none";
    projectCard.style.display = "block";
    btnSingle.className = "btn btn-secondary btn-sm";
    btnProject.className = "btn btn-primary btn-sm";
  }
}

function fillTestPackage(name, version = "") {
  document.getElementById("inputPackageName").value = name;
  document.getElementById("inputPackageVersion").value = version;
}

async function handleSingleScan(e) {
  if (e && e.preventDefault) e.preventDefault();

  const pkgName = document.getElementById("inputPackageName").value.trim();
  const pkgVersion = document.getElementById("inputPackageVersion").value.trim() || null;

  if (!pkgName) {
    alert("Please enter an NPM package name.");
    return;
  }

  const btn = document.getElementById("btnRunSingleScan");
  const btnText = document.getElementById("btnRunSingleText");
  const progressCard = document.getElementById("scanProgressCard");
  const progressTitle = document.getElementById("scanProgressTitle");
  const progressDesc = document.getElementById("scanProgressDesc");

  btn.disabled = true;
  btnText.textContent = "Analyzing...";
  progressCard.style.display = "block";
  progressTitle.textContent = `Analyzing ${pkgName}...`;
  progressDesc.textContent = "Downloading tarball from NPM Registry and executing static AST heuristics & OSV checks...";

  try {
    const scanResult = await API.scanPackage(pkgName, pkgVersion);
    
    // On completion, navigate directly to report view and display results
    window.currentScanId = scanResult.id;
    await loadReport(scanResult.id);
    navigateTo("report");
  } catch (err) {
    alert(`Scan error: ${err.message}`);
  } finally {
    btn.disabled = false;
    btnText.textContent = "Analyze Package";
    progressCard.style.display = "none";
  }
}

// Manifest Upload & Drag/Drop
const dropzone = document.getElementById("manifestDropzone");

if (dropzone) {
  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone.addEventListener("dragleave", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setManifestFile(e.dataTransfer.files[0]);
    }
  });
}

function handleManifestFileSelect(e) {
  if (e.target.files && e.target.files[0]) {
    setManifestFile(e.target.files[0]);
  }
}

function setManifestFile(file) {
  selectedManifestFile = file;
  const display = document.getElementById("fileSelectedDisplay");
  display.style.display = "inline-flex";
  display.className = "selected-file-badge";
  display.innerHTML = `
    <span><strong>${escapeHtml(file.name)}</strong> (${(file.size / 1024).toFixed(1)} KB)</span>
    <button type="button" style="background:none; border:none; color:var(--severity-high); cursor:pointer; font-weight:bold;" onclick="clearManifestFile(event)">✕</button>
  `;
}

function clearManifestFile(e) {
  if (e) e.stopPropagation();
  selectedManifestFile = null;
  document.getElementById("manifestFileInput").value = "";
  const display = document.getElementById("fileSelectedDisplay");
  display.style.display = "none";
  display.innerHTML = "";
}

function loadSampleManifest() {
  const sample = {
    "name": "sample-node-app",
    "version": "1.0.0",
    "dependencies": {
      "express": "^4.22.2",
      "minivlad": "*"
    },
    "devDependencies": {
      "joi": "17.13.8"
    }
  };
  document.getElementById("rawManifestContent").value = JSON.stringify(sample, null, 2);
}

async function handleProjectScan() {
  const rawContent = document.getElementById("rawManifestContent").value.trim();

  if (!selectedManifestFile && !rawContent) {
    alert("Please select a manifest file or paste package.json content.");
    return;
  }

  const btn = document.getElementById("btnRunProjectScan");
  const btnText = document.getElementById("btnRunProjectText");
  const progressCard = document.getElementById("scanProgressCard");
  const progressTitle = document.getElementById("scanProgressTitle");
  const progressDesc = document.getElementById("scanProgressDesc");

  btn.disabled = true;
  btnText.textContent = "Auditing dependencies...";
  progressCard.style.display = "block";
  progressTitle.textContent = "Auditing project dependencies...";
  progressDesc.textContent = "Resolving direct and transitive dependency trees and querying vulnerability advisories...";

  try {
    const formData = new FormData();
    if (selectedManifestFile) {
      formData.append("file", selectedManifestFile);
    } else {
      formData.append("raw_content", rawContent);
    }

    const scanResult = await API.scanProject(formData);
    window.currentScanId = scanResult.id;
    await loadReport(scanResult.id);
    navigateTo("report");
  } catch (err) {
    alert(`Project scan failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btnText.textContent = "Audit Dependencies";
    progressCard.style.display = "none";
  }
}
