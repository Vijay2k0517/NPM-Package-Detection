import logging
from typing import List, Dict, Any, Tuple
from backend.app.config import settings

logger = logging.getLogger("ai_explainer")


class AIExplainerService:
    def __init__(self):
        self.gemini_key = settings.GEMINI_API_KEY
        self.openai_key = settings.OPENAI_API_KEY
        self.provider = settings.LLM_PROVIDER

    def generate_explanation(
        self,
        package_name: str,
        version: str,
        risk_score: float,
        risk_level: str,
        findings: List[Dict[str, Any]],
        metadata: Dict[str, Any]
    ) -> Tuple[str, List[str], str]:
        """
        Generates:
        - ai_explanation: plain language narrative
        - recommendations: actionable security steps
        - provider: name of the generator ('deterministic', 'gemini', or 'openai')
        """
        # If external LLM key is configured, try calling it
        if self.gemini_key and self.provider == "gemini":
            try:
                res = self._call_gemini(package_name, version, risk_score, findings, metadata)
                if res:
                    return res[0], res[1], "gemini"
            except Exception as e:
                logger.warning(f"Gemini LLM call failed, falling back to deterministic: {e}")

        elif self.openai_key and self.provider == "openai":
            try:
                res = self._call_openai(package_name, version, risk_score, findings, metadata)
                if res:
                    return res[0], res[1], "openai"
            except Exception as e:
                logger.warning(f"OpenAI LLM call failed, falling back to deterministic: {e}")

        # Deterministic Expert Security Engine (always available, safe, offline, fast)
        return self._generate_deterministic(package_name, version, risk_score, risk_level, findings, metadata)

    def _generate_deterministic(
        self,
        package_name: str,
        version: str,
        risk_score: float,
        risk_level: str,
        findings: List[Dict[str, Any]],
        metadata: Dict[str, Any]
    ) -> Tuple[str, List[str], str]:
        recs = []

        if risk_score == 0.0:
            explanation = (
                f"Security evaluation for '{package_name}@{version}' completed with a risk score of 0.0/100 (Low Risk). "
                f"Static analysis of package source code, registry metadata, and known vulnerability databases did not identify "
                f"any suspicious code execution, obfuscation, or reported CVEs. "
                f"\n\nNote: A score of 0 indicates that no known threat patterns were detected; it does not guarantee complete absence "
                f"of undiscovered zero-day logic."
            )
            recs = [
                f"Package appears clean based on current static heuristics and OSV databases.",
                "Ensure dependency lockfiles (package-lock.json) pin the exact resolved hash.",
                "Continue monitoring future releases for newly reported advisories."
            ]
            return explanation, recs, "deterministic"

        # High/Critical risk narrative
        vuln_count = sum(1 for f in findings if f.get("source") == "vulnerability")
        static_count = sum(1 for f in findings if f.get("source") == "static_analysis")
        corr_count = sum(1 for f in findings if f.get("source") == "behavior_correlation")

        critical_findings = [f for f in findings if f.get("severity") in ["critical", "high"]]

        highlights = []
        for cf in critical_findings[:3]:
            loc = f" in {cf['file_path']}:{cf['line_number']}" if cf.get("file_path") and cf.get("line_number") else ""
            highlights.append(f"• {cf['title']}{loc}: {cf['description']}")

        highlights_str = "\n".join(highlights) if highlights else "• Multiple suspicious code or metadata anomalies detected."

        explanation = (
            f"Security analysis for '{package_name}@{version}' determined a risk score of {risk_score}/100 ({risk_level.upper()} RISK). "
            f"The package triggered {len(findings)} total security indicators across {vuln_count} known advisories, "
            f"{static_count} static code pattern alerts, and {corr_count} correlated attack chain behaviors.\n\n"
            f"Key Observations:\n{highlights_str}\n\n"
            f"Impact Assessment: Incorporating this package may expose your build environment or runtime servers to "
            f"unauthorized code execution, credential exfiltration, or backdoors. An attacker could exploit these capabilities "
            f"to compromise developer secrets or client data."
        )

        # Dynamic recommendations
        recs.append("Do not install or execute this package in production or CI/CD pipelines.")
        if any("base64" in f.get("rule_id", "") or "eval" in f.get("rule_id", "") for f in findings):
            recs.append("Manually inspect the decoded payload to verify whether obfuscated code was injected.")
        if vuln_count > 0:
            recs.append(f"Upgrade '{package_name}' to a patched release that addresses identified CVEs.")
        if metadata.get("is_typosquatting"):
            target = metadata.get("typosquatting_target", "the genuine package")
            recs.append(f"Verify typosquatting: Check if you intended to install '{target}' instead.")
        if metadata.get("has_install_scripts"):
            recs.append("Inspect npm lifecycle scripts (preinstall/postinstall) for unauthorized shell invocations.")

        return explanation, recs, "deterministic"

    def _call_gemini(self, package_name: str, version: str, risk_score: float, findings: List[Dict[str, Any]], metadata: Dict[str, Any]):
        import requests
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_key}"
        prompt = (
            f"You are a cybersecurity AI analyst. Provide a brief 2-paragraph security explanation and 3 bullet recommendations "
            f"for NPM package {package_name}@{version} with risk score {risk_score}/100. "
            f"Findings: {[f['title'] for f in findings[:5]]}. Return valid text."
        )
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            return text, ["Audit package source thoroughly.", "Do not run in privileged environments."], "gemini"
        return None

    def _call_openai(self, package_name: str, version: str, risk_score: float, findings: List[Dict[str, Any]], metadata: Dict[str, Any]):
        import requests
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.openai_key}"}
        prompt = (
            f"You are a cybersecurity AI analyst. Provide a brief 2-paragraph security explanation "
            f"for NPM package {package_name}@{version} with risk score {risk_score}/100. "
            f"Findings: {[f['title'] for f in findings[:5]]}."
        )
        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 400
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=10)
        if resp.status_code == 200:
            text = resp.json()["choices"][0]["message"]["content"]
            return text, ["Audit package source thoroughly.", "Do not run in privileged environments."], "openai"
        return None
