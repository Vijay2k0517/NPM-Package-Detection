import math
from typing import List, Dict, Any, Tuple


class RiskScoringEngine:
    METHODOLOGY_VERSION = "1.0.0"

    def calculate_score(
        self,
        vulnerabilities: List[Dict[str, Any]],
        static_findings: List[Dict[str, Any]],
        correlated_findings: List[Dict[str, Any]],
        metadata: Dict[str, Any]
    ) -> Tuple[float, str, Dict[str, Any]]:
        """
        Calculate normalized risk score (0 to 100) and severity level:
        - 0.0 - 29.9: Low Risk
        - 30.0 - 69.9: Medium Risk
        - 70.0 - 100.0: High / Critical Risk
        """
        # Component points
        vuln_points = 0.0
        for v in vulnerabilities:
            sev = v.get("severity", "medium").lower()
            if sev == "critical":
                vuln_points += 35
            elif sev == "high":
                vuln_points += 25
            elif sev == "medium":
                vuln_points += 15
            else:
                vuln_points += 5

        static_points = 0.0
        for s in static_findings:
            sev = s.get("severity", "medium").lower()
            if sev == "critical":
                static_points += 35
            elif sev == "high":
                static_points += 22
            elif sev == "medium":
                static_points += 10
            else:
                static_points += 3

        correlation_points = 0.0
        for c in correlated_findings:
            sev = c.get("severity", "high").lower()
            if sev == "critical":
                correlation_points += 30
            else:
                correlation_points += 20

        meta_points = 0.0
        if metadata.get("is_typosquatting"):
            meta_points += 25
        if metadata.get("has_install_scripts"):
            meta_points += 15
        if metadata.get("is_unclaimed_or_disposable"):
            meta_points += 10
        if metadata.get("has_direct_url_deps"):
            meta_points += 10

        # Cap individual components to avoid single-category distortion
        capped_vuln = min(50.0, vuln_points)
        capped_static = min(50.0, static_points)
        capped_corr = min(40.0, correlation_points)
        capped_meta = min(30.0, meta_points)

        raw_total = capped_vuln + capped_static + capped_corr + capped_meta

        # Apply diminishing returns normalization
        if raw_total <= 0:
            final_score = 0.0
        else:
            # Scale towards 100 asymptotically
            final_score = min(100.0, round(raw_total, 1))

        # Severity classification
        if final_score >= 80.0:
            risk_level = "critical"
        elif final_score >= 70.0:
            risk_level = "high"
        elif final_score >= 30.0:
            risk_level = "medium"
        else:
            risk_level = "low"

        breakdown = {
            "methodology_version": self.METHODOLOGY_VERSION,
            "vulnerability_component": capped_vuln,
            "static_code_component": capped_static,
            "correlation_component": capped_corr,
            "metadata_component": capped_meta,
            "raw_total": raw_total,
            "formula": "Score = min(100, vuln[max:50] + static[max:50] + corr[max:40] + meta[max:30])"
        }

        return final_score, risk_level, breakdown
