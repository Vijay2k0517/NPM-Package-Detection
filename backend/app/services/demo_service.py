import datetime
import uuid
from typing import Dict, Any


class DemoService:
    @staticmethod
    def get_demo_scan(package_name: str, version: str = "1.0.0") -> Dict[str, Any]:
        """Generate deterministic demo scan data clearly marked as demonstration data."""
        scan_id = str(uuid.uuid4())
        is_malicious = "mal" in package_name.lower() or "vlad" in package_name.lower() or "evil" in package_name.lower()

        if is_malicious:
            score = 85.0
            level = "critical"
            findings = [
                {
                    "id": f"demo-f-1-{scan_id[:8]}",
                    "title": "Base64 Decoding with Immediate Execution",
                    "severity": "critical",
                    "description": "Detected base64 payload decoding followed by direct execution in eval().",
                    "source": "static_analysis",
                    "file_path": "package/index.js",
                    "line_number": 3,
                    "code_snippet": "// ruleid: eval-call\neval(atob(str));",
                    "matched_pattern": "atob(",
                    "impact": "Arbitrary code execution on target machine upon import.",
                    "confidence": "confirmed",
                    "recommendation": "Do not execute or install this package.",
                    "rule_id": "threat-runtime-obfuscation-base64exec",
                    "references": ["https://attack.mitre.org/tactics/TA0005/"]
                },
                {
                    "id": f"demo-f-2-{scan_id[:8]}",
                    "title": "Correlated Attack Chain: Defense Evasion & Payload Execution",
                    "severity": "critical",
                    "description": "Obfuscated encoding combined with dynamic execution and environment access.",
                    "source": "behavior_correlation",
                    "file_path": "package/index.js",
                    "line_number": 3,
                    "code_snippet": "eval(atob(str));",
                    "matched_pattern": "eval",
                    "impact": "Hides backdoor execution from code reviewers.",
                    "confidence": "high",
                    "recommendation": "Block this package immediately.",
                    "rule_id": "attack-chain-defense-evasion",
                    "references": ["https://attack.mitre.org/tactics/TA0005/"]
                }
            ]
            summary = "DEMO SCAN: Multiple critical backdoor indicators and dynamic obfuscation observed."
            explanation = "DEMO EVALUATION: This demonstration scan simulates a high-risk malicious package with obfuscated payload execution."
            recs = ["Do not use in production.", "Inspect decoded payload."]
            meta = {
                "name": package_name,
                "version": version,
                "description": "Demonstration malicious npm package for security testing.",
                "author": "Anonymous Attacker",
                "author_email": "threat@disposable-domain.xyz",
                "license": "MIT",
                "has_install_scripts": True,
                "install_scripts_detail": {"preinstall": "node index.js"},
                "is_typosquatting": False,
                "is_unclaimed_or_disposable": True,
                "has_direct_url_deps": False
            }
        else:
            score = 0.0
            level = "low"
            findings = []
            summary = "DEMO SCAN: Zero threat indicators or reported vulnerabilities found."
            explanation = "DEMO EVALUATION: Clean package demonstration. All static heuristics passed."
            recs = ["Package is verified as safe in demo environment."]
            meta = {
                "name": package_name,
                "version": version,
                "description": "Demonstration clean package.",
                "author": "Verified Publisher",
                "author_email": "publisher@npm-verified.org",
                "license": "MIT",
                "has_install_scripts": False,
                "install_scripts_detail": {},
                "is_typosquatting": False,
                "is_unclaimed_or_disposable": False,
                "has_direct_url_deps": False
            }

        return {
            "id": scan_id,
            "package_name": package_name,
            "version": version,
            "scan_type": "package",
            "status": "completed",
            "risk_score": score,
            "risk_level": level,
            "critical_count": 2 if is_malicious else 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "total_findings": len(findings),
            "summary": summary,
            "ai_explanation": explanation,
            "ai_provider": "deterministic-demo",
            "recommendations": recs,
            "score_breakdown": {"demo_mode": True, "base_score": score},
            "is_demo": True,
            "error_message": None,
            "created_at": datetime.datetime.now(datetime.timezone.utc),
            "completed_at": datetime.datetime.now(datetime.timezone.utc),
            "findings": findings,
            "package_metadata": meta,
            "dependencies": []
        }
