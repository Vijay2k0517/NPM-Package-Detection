import os
import re
import math
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger("static_analyzer")

# Compiled heuristics patterns
PATTERNS = [
    {
        "id": "eval-dynamic-code",
        "title": "Dynamic Code Evaluation (eval / Function)",
        "severity": "high",
        "regex": re.compile(r"\b(eval\s*\([^\)]*|Function\s*\([^\)]*\)\s*\()", re.IGNORECASE),
        "impact": "Arbitrary code execution at runtime bypassing static verification.",
        "description": "Detected dynamic execution of JavaScript strings using eval() or new Function().",
        "recommendation": "Refactor to use standard imports and eliminate dynamic code execution."
    },
    {
        "id": "obfuscation-base64-exec",
        "title": "Base64 Decoding with Immediate Execution",
        "severity": "critical",
        "regex": re.compile(r"(eval\s*\(\s*(atob|Buffer\.from)\s*\([^\)]+\)\.toString\s*\(\s*['\"]utf-?8['\"]\s*\)\s*\)|eval\s*\(\s*atob\s*\()", re.IGNORECASE),
        "impact": "Known malware delivery pattern used to hide payloads from code reviewers.",
        "description": "Detected base64 payload decoding followed by direct execution in eval().",
        "recommendation": "Review the decoded payload immediately. This pattern is strongly indicative of malicious backdoor code."
    },
    {
        "id": "process-spawn-shell",
        "title": "Child Process Shell Execution",
        "severity": "high",
        "regex": re.compile(r"(\b(child_process|cp)\.(exec|execSync|spawn|spawnSync)|require\s*\(\s*['\"]child_process['\"]\s*\)\.(exec|execSync|spawn|spawnSync)|\bexec\s*\(\s*['\"`](sh|bash|cmd|powershell|curl|wget))\b", re.IGNORECASE),
        "impact": "Enables arbitrary system commands and remote shell access on the host system.",
        "description": "Package executes system shells (bash, powershell, cmd) or downloaders via child_process.",
        "recommendation": "Ensure no external binaries are launched without explicit user consent."
    },
    {
        "id": "sensitive-file-access",
        "title": "Access to Sensitive Files / Credentials",
        "severity": "high",
        "regex": re.compile(r"(\.ssh[/\\]id_|\.env|\.aws[/\\]credentials|\.npmrc|/etc/shadow|/etc/passwd)", re.IGNORECASE),
        "impact": "Exfiltration of developer credentials, SSH keys, or environment secrets.",
        "description": "Detected file paths accessing SSH keys, environment variables, or cloud credentials.",
        "recommendation": "Ensure the package has no legitimate reason to read private credentials or dotfiles."
    },
    {
        "id": "network-socket-reverse-shell",
        "title": "Reverse Shell / Raw Socket Connection",
        "severity": "critical",
        "regex": re.compile(r"(net\.Socket\s*\(\s*\)\s*\.connect|require\s*\(\s*['\"]net['\"]\s*\)\.createConnection)", re.IGNORECASE),
        "impact": "Allows attackers to establish bidirectional command and control (C2) tunnels.",
        "description": "Detected raw TCP socket creation commonly associated with reverse shell backdoors.",
        "recommendation": "Inspect socket target endpoints. General libraries should not initiate raw TCP socket tunnels."
    },
    {
        "id": "discord-webhook-exfil",
        "title": "Exfiltration via Discord / Telegram / Webhook",
        "severity": "high",
        "regex": re.compile(r"(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pipedream\.net|webhook\.site)", re.IGNORECASE),
        "impact": "Data exfiltration channel sending sensitive tokens to attacker-controlled chat channels.",
        "description": "Detected hardcoded communication with webhook APIs commonly abused for token theft.",
        "recommendation": "Remove any telemetry or logging to unauthorized third-party chat webhooks."
    },
    {
        "id": "obfuscation-hex-charcode",
        "title": "Hex Character Code Mangling / Obfuscation",
        "severity": "medium",
        "regex": re.compile(r"(\\x[0-9a-fA-F]{2}){4,}|String\.fromCharCode\s*\(\s*(\d+\s*,\s*){3,}", re.IGNORECASE),
        "impact": "Conceals malicious URLs or code strings from manual inspection.",
        "description": "Detected sequential hex-escaped characters or fromCharCode arrays used to hide strings.",
        "recommendation": "Deobfuscate strings to verify intent."
    }
]


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy to flag heavily packed/obfuscated code."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return entropy


class StaticSourceAnalyzer:
    def __init__(self):
        self.patterns = PATTERNS

    def analyze_directory(self, source_dir: str) -> List[Dict[str, Any]]:
        """
        Walk all source code files in directory and detect suspicious patterns.
        """
        findings = []
        source_path = Path(source_dir)
        if not source_path.exists():
            return findings

        # Also attempt GuardDog YARA scanning if available
        guarddog_findings = self._run_guarddog_yara(source_dir)
        findings.extend(guarddog_findings)

        # Inspect JS, CJS, MJS, JSON files
        valid_extensions = {".js", ".cjs", ".mjs", ".json"}
        
        for root, _, files in os.walk(source_dir):
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() not in valid_extensions:
                    continue

                rel_path = str(file_path.relative_to(source_path))

                # Skip standard minified vendor files if exceedingly large (>2MB)
                try:
                    if file_path.stat().st_size > 2 * 1024 * 1024:
                        continue
                    
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                except Exception as e:
                    logger.debug(f"Unable to read file {rel_path}: {e}")
                    continue

                full_content = "".join(lines)

                # Heuristic pattern checks per line
                for line_idx, line in enumerate(lines, start=1):
                    # Clean line
                    stripped = line.strip()
                    if not stripped or stripped.startswith(("//", "/*", "*")):
                        continue

                    for pattern in self.patterns:
                        match = pattern["regex"].search(line)
                        if match:
                            matched_text = match.group(0)
                            
                            # Grab context snippet (up to 3 lines)
                            start_line = max(0, line_idx - 2)
                            end_line = min(len(lines), line_idx + 1)
                            snippet = "".join(lines[start_line:end_line]).strip()

                            findings.append({
                                "id": f"{pattern['id']}-{rel_path}-{line_idx}",
                                "title": pattern["title"],
                                "severity": pattern["severity"],
                                "description": pattern["description"],
                                "source": "static_analysis",
                                "file_path": rel_path,
                                "line_number": line_idx,
                                "code_snippet": snippet[:500],
                                "matched_pattern": matched_text[:100],
                                "impact": pattern["impact"],
                                "confidence": "high",
                                "recommendation": pattern["recommendation"],
                                "rule_id": pattern["id"],
                                "references": []
                            })

                # Check high entropy (obfuscated single file)
                if len(full_content) > 300 and _shannon_entropy(full_content[:1000]) > 5.8:
                    if not any(f["rule_id"] == "high-entropy-obfuscation" and f["file_path"] == rel_path for f in findings):
                        findings.append({
                            "id": f"entropy-{rel_path}",
                            "title": "High Shannon Entropy (Packed / Obfuscated Code)",
                            "severity": "medium",
                            "description": f"File '{rel_path}' exhibits high Shannon entropy (>5.8), suggesting packed or encrypted strings.",
                            "source": "static_analysis",
                            "file_path": rel_path,
                            "line_number": 1,
                            "code_snippet": full_content[:200] + "...",
                            "matched_pattern": "high_entropy",
                            "impact": "Prevents static analysis from reading the underlying executable payload.",
                            "confidence": "medium",
                            "recommendation": "Review unpacked source code from author's repository.",
                            "rule_id": "high-entropy-obfuscation",
                            "references": []
                        })

        return findings

    def _run_guarddog_yara(self, source_dir: str) -> List[Dict[str, Any]]:
        """Run integrated GuardDog analyzer YARA heuristics if available."""
        findings = []
        try:
            from guarddog.analyzer.analyzer import Analyzer
            from guarddog.ecosystems import ECOSYSTEM

            analyzer = Analyzer(ECOSYSTEM.NPM)
            results = analyzer.analyze_sourcecode(source_dir)
            
            for rule_id, matches in results.items():
                if not matches:
                    continue
                for match in matches:
                    file_path = match.get("file", "package")
                    line_no = match.get("line_number")
                    code = match.get("code", "")
                    
                    # Convert to our Finding format
                    findings.append({
                        "id": f"guarddog-{rule_id}-{file_path}",
                        "title": f"Heuristic Rule: {rule_id}",
                        "severity": "high" if "threat" in rule_id else "medium",
                        "description": f"YARA heuristic '{rule_id}' matched package source code.",
                        "source": "static_analysis",
                        "file_path": file_path,
                        "line_number": line_no,
                        "code_snippet": code[:500] if code else None,
                        "matched_pattern": rule_id,
                        "impact": "Identified behavior characteristic of known malicious supply chain attacks.",
                        "confidence": "high",
                        "recommendation": "Verify whether this capability is necessary for the package's declared purpose.",
                        "rule_id": rule_id,
                        "references": ["https://github.com/DataDog/guarddog"]
                    })
        except Exception as e:
            logger.debug(f"GuardDog YARA runner skipped or not applicable: {e}")
        return findings
