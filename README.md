# NPM Shield AI
## AI-Based Malicious NPM Package Detection & Risk Assessment

**NPM Shield AI** is a professional full-stack cybersecurity web application designed to help software engineers, security analysts, and DevSecOps teams detect potentially malicious NPM packages, evaluate supply-chain risks, inspect obfuscated payloads, and correlate complex multi-stage attack chains before incorporating dependencies into production applications.

---

## 🎯 Key Capabilities

- **Real NPM Registry Ingestion**: Safely streams metadata, tarball archives, and version manifests directly from `https://registry.npmjs.org` without running arbitrary install scripts. Supports scoped packages (e.g. `@scope/package`).
- **Live Known Vulnerability Checking**: Real-time integration with the **OSV.dev (Open Source Vulnerabilities)** API, mapping GHSA and CVE advisories, affected semantic version ranges, and fixed releases.
- **Static AST & Heuristic Code Analysis**:
  - Base64 payload decoding with direct evaluation (`eval(atob(...))`, `Buffer.from(...).toString()`).
  - Child process spawning and shell execution (`cp.exec`, `child_process.spawnSync`, `bash`, `powershell`, `cmd`, `curl`).
  - Sensitive environment and credential dotfile access (`.env`, `.ssh/id_*`, `.aws/credentials`, `/etc/shadow`).
  - Reverse shell sockets and raw TCP tunnels (`net.Socket().connect`).
  - Webhook exfiltration channels (`discord.com/api/webhooks`, `api.telegram.org`, `pipedream.net`).
  - Shannon entropy scanning for heavily packed/encrypted JavaScript code.
  - Integrated GuardDog YARA source-code rules.
- **Behaviour Correlation Engine**: Correlates multiple suspicious indicators into MITRE ATT&CK stages:
  - *Defense Evasion & Dynamic Execution Chain* (TA0005)
  - *Credential Theft & Exfiltration Attack Chain* (TA0010)
  - *Supply Chain Dropper* (Typosquatting + Lifecycle Install Script)
- **Transparent 0–100 Risk Scoring**: Mathematical scoring model with component caps, confidence separation, and documented methodology (Version 1.0.0).
- **Project Dependency & Lockfile Auditing**: Drag-and-drop parser for `package.json`, `package-lock.json` (v1, v2, v3), and `npm-shrinkwrap.json`, mapping direct vs. transitive dependency paths.
- **AI-Assisted Explanations**: Plain-language risk summaries and remediation steps powered by configurable LLMs (Gemini / OpenAI), with automatic fallback to a deterministic security engine when offline.
- **Comprehensive Reporting & Export**: Instant export of complete audit findings and dependency paths in JSON and CSV formats.
- **Deterministic Demo Mode**: Safely test and demo real vs. simulated threats without requiring external registry queries.

---

## 🧱 Architecture & Technology Stack

The project strictly follows the required technology constraints:
- **Frontend**: Semantic HTML5, Vanilla CSS3 (custom SaaS light design system), Vanilla JavaScript (ES6+), Fetch API, SVG/CSS visualizations. **Zero external JS/CSS frameworks** (No React, Vue, Angular, TypeScript, Tailwind, or Bootstrap).
- **Backend**: Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2.x ORM, SQLite (`npm_shield.db`).

### Project Layout

```
NPM Shield AI/
├── backend/
│   ├── app/
│   │   ├── main.py                   # FastAPI server entrypoint & static mounting
│   │   ├── config.py                 # Pydantic Settings & environment variables
│   │   ├── database.py               # SQLAlchemy engine & SQLite session factory
│   │   ├── models/                   # Database ORM models
│   │   │   ├── scan.py               # Scan records & status tracking
│   │   │   ├── package.py            # Package metadata & supply-chain attributes
│   │   │   ├── finding.py            # Security findings, snippets & evidence
│   │   │   └── dependency.py         # Direct & transitive project dependencies
│   │   ├── schemas/                  # Pydantic v2 request & response schemas
│   │   │   └── scan.py               # DTOs with ConfigDict(from_attributes=True)
│   │   ├── routers/                  # Modular API endpoints
│   │   │   ├── overview.py           # Dashboard KPIs & metrics
│   │   │   ├── scans.py              # Package & project scanning, history
│   │   │   ├── packages.py           # Live registry metadata checks
│   │   │   ├── dependencies.py       # Transitive dependency trees
│   │   │   └── reports.py            # JSON & CSV report generators
│   │   ├── services/                 # Business logic & analyzers
│   │   │   ├── npm_registry.py       # Registry ingestion, tar extraction, typosquatting
│   │   │   ├── vulnerability_service.py # OSV.dev vulnerability queries
│   │   │   ├── static_analyzer.py    # Static pattern & Shannon entropy analysis
│   │   │   ├── dependency_analyzer.py# Manifest & lockfile parser
│   │   │   ├── behaviour_analyzer.py # MITRE ATT&CK correlation engine
│   │   │   ├── risk_scoring.py       # Transparent 0-100 scoring engine
│   │   │   ├── ai_explainer.py       # Gemini / OpenAI / Deterministic explainer
│   │   │   ├── report_generator.py   # Formatted report generation
│   │   │   └── demo_service.py       # Deterministic demo scanning service
│   │   └── utils/
│   │       └── sanitizer.py          # Path traversal and input sanitization
│   ├── tests/                        # Automated Pytest suite (17 tests)
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── index.html                    # Single-page interface with 7 primary views
│   ├── css/
│   │   ├── styles.css                # Color tokens & typography (SaaS light theme)
│   │   ├── layout.css                # Grid & flexbox layouts
│   │   ├── components.css            # Buttons, tables, badges, modals, empty states
│   │   └── responsive.css            # Tablet and mobile breakpoints
│   └── js/
│       ├── app.js                    # View routing & application bootstrap
│       ├── api.js                    # Fetch API client wrapper
│       ├── dashboard.js              # Overview metrics & risk distribution SVG
│       ├── scanner.js                # Single package & file upload controllers
│       ├── report.js                 # Expandable findings, snippets & AI recommendations
│       ├── dependencies.js           # Searchable table & interactive SVG graph
│       ├── history.js                # Filterable scan history table
│       ├── reports.js                # JSON / CSV export trigger
│       ├── settings.js               # Functional environment & status view
│       └── utils.js                  # Formatting, dates, severity badges
├── examples/                         # Manifest samples for testing
├── npm_shield.db                     # SQLite database file
├── requirements.txt                  # Root dependencies
├── .env.example                      # Root configuration template
├── run.bat                           # 1-click Windows server launcher
├── scan.bat                          # CLI & Web launcher
└── README.md                         # Documentation
```

---

## 🚀 Quickstart & Run Instructions

### Prerequisites
- Python 3.10+ (Tested with Python 3.12)
- Modern web browser (Chrome, Edge, Firefox, Safari)

### Option 1: One-Click Launch (Windows)
Double-click `run.bat` or run in PowerShell / Command Prompt:
```cmd
.\run.bat
```
The server will start at **http://127.0.0.1:8000** and serve the full application.

### Option 2: Standard Python Setup (Windows / Linux / macOS)

1. **Create and activate a virtual environment (optional but recommended):**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux / macOS:
   source venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **(Optional) Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   *Edit `.env` to configure an optional Gemini or OpenAI API key if desired.*

4. **Start the server:**
   ```bash
   python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

5. **Open the application:**
   Navigate to **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

---

## 🧪 Running the Test Suite

Run the full automated test suite containing 17 unit and integration tests:

```bash
python -m pytest backend/tests -v
```

Tests cover:
- API health check (`GET /api/health`)
- Overview metrics and settings endpoints
- Validation of package names and empty inputs
- Demo mode scanning and database persistence
- Scan history retrieval and filtering
- JSON and CSV report export formats
- Static source analysis (dynamic execution, obfuscated base64, process spawning)
- Manifest & lockfile v1/v2/v3 parsing
- MITRE ATT&CK behaviour correlation chains
- Levenshtein distance & typosquatting heuristics
- Vulnerability service parsing with OSV mock data
- Transparent risk scoring calculations

---

## 📊 Risk Scoring Methodology (v1.0.0)

Risk scores are normalized between **0.0 and 100.0** to provide transparent, explainable metrics without false claims of absolute safety:

| Severity Level | Score Range | Meaning |
| :--- | :---: | :--- |
| **Low** | `0.0 – 39.9` | No confirmed threats. Standard package hygiene recommended. |
| **Medium** | `40.0 – 69.9` | Suspicious indicators (e.g. install scripts, moderate entropy) or medium CVEs detected. |
| **High** | `70.0 – 89.9` | Confirmed vulnerabilities, shell spawning, or potential typosquatting detected. |
| **Critical** | `90.0 – 100.0` | Active multi-stage attack chain (e.g. obfuscated dynamic exec, credential exfiltration). |

### Scoring Component Weights & Caps:
- **Known Vulnerabilities**: Critical = +40 pts, High = +25 pts, Medium = +15 pts, Low = +5 pts *(capped at 50 pts)*.
- **Static Code Findings**: Critical = +30 pts, High = +15 pts, Medium = +8 pts, Low = +3 pts *(capped at 40 pts)*.
- **Correlated Behaviour Patterns**: +35 pts per multi-stage attack chain *(capped at 50 pts)*.
- **Supply-Chain Metadata Heuristics**:
  - Typosquatting against popular package: +25 pts
  - Lifecycle install scripts (`preinstall` / `postinstall`): +15 pts
  - Disposable or unclaimed author email: +10 pts
  - Direct git / HTTP URL dependencies: +10 pts

---

## 🌐 REST API Endpoints

All endpoints are versioned and documented under `/api`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Health check endpoint returning service status. |
| `GET` | `/api/overview` | Aggregated dashboard metrics, scan totals, and risk distribution. |
| `GET` | `/api/settings` | Server runtime settings, LLM provider status, and engine information. |
| `POST` | `/api/scans/package` | Initiate a single package scan (`package_name`, optional `version`, `is_demo`). |
| `POST` | `/api/scans/project` | Upload and audit `package.json`, `package-lock.json`, or `shrinkwrap`. |
| `GET` | `/api/scans` | Retrieve historical scan records with search, sorting, and severity filtering. |
| `GET` | `/api/scans/{scan_id}` | Retrieve real-time scan status, findings, and metadata. |
| `GET` | `/api/scans/{scan_id}/dependencies` | Retrieve direct and transitive dependency trees for a scan. |
| `GET` | `/api/scans/{scan_id}/export?format=json` | Download full analysis report in JSON format. |
| `GET` | `/api/scans/{scan_id}/export?format=csv` | Download findings report in CSV format. |
| `POST` | `/api/scans/{scan_id}/rescan` | Re-trigger an analysis for an existing package. |
| `DELETE` | `/api/scans/{scan_id}` | Delete a scan record and all associated findings from SQLite. |
| `GET` | `/api/packages/{name}/metadata` | Query live NPM registry metadata without running a scan. |

---

## 🔒 Security Best Practices & Isolation

1. **No Untrusted Execution on Host**:
   - NPM Shield AI parses tarballs and inspects AST/regex patterns in memory without ever running `npm install` or executing package lifecycle scripts on the host machine.
2. **Path Traversal Protection**:
   - Tarball extraction and file upload paths are validated against `..` and sanitized against directory escapes.
3. **Safe Dynamic Analysis Posture**:
   - Untrusted dynamic execution in host processes is disabled by default (`ENABLE_DYNAMIC_ANALYSIS=False`). Dynamic sandboxing requires a disposable container or VM boundary.
4. **Transparent Safety Posture**:
   - Packages with 0 findings are explicitly marked with: *"No suspicious indicators detected during static analysis. This does not guarantee the package is completely safe."*

---

## 📄 License
This project is open-source under the MIT License.
