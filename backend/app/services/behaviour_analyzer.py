import logging
from typing import List, Dict, Any

logger = logging.getLogger("behaviour_analyzer")


class BehaviourCorrelationEngine:
    def correlate_findings(self, static_findings: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze the cross-correlation between different indicators:
        - Obfuscation + Dynamic Execution = Defense Evasion & Hidden Backdoor
        - Sensitive File Read + Network Request = Credential Exfiltration Attack Chain
        - Typosquatting + Install Script = Malicious Dropper
        - Reverse Shell Socket = Remote Access Trojan (RAT)
        """
        correlated_findings = []
        rule_ids = {f.get("rule_id", "") for f in static_findings}
        
        has_eval = any("eval" in r for r in rule_ids)
        has_base64 = any("base64" in r for r in rule_ids)
        has_shell = any("process" in r or "shell" in r for r in rule_ids)
        has_sensitive_file = any("sensitive" in r or "file" in r for r in rule_ids)
        has_network = any("network" in r or "socket" in r or "discord" in r or "webhook" in r for r in rule_ids)
        has_install_script = metadata.get("has_install_scripts", False)
        is_typosquatting = metadata.get("is_typosquatting", False)

        # 1. Defense Evasion: Obfuscation + Exec
        if (has_base64 or has_eval) and (has_shell or "obfuscation" in str(rule_ids)):
            correlated_findings.append({
                "id": "corr-defense-evasion-chain",
                "title": "Correlated Attack Chain: Defense Evasion & Payload Execution",
                "severity": "critical",
                "description": "Correlated indicators show obfuscated encoding combined with dynamic execution and process creation.",
                "source": "behavior_correlation",
                "impact": "Indicates intentional concealment of malicious execution from standard SAST scanners.",
                "confidence": "high",
                "recommendation": "Block usage of this package. Manual code deobfuscation is strictly recommended before running.",
                "rule_id": "attack-chain-defense-evasion",
                "references": ["https://attack.mitre.org/tactics/TA0005/"]
            })

        # 2. Exfiltration: Sensitive File + Outbound
        if has_sensitive_file and has_network:
            correlated_findings.append({
                "id": "corr-credential-exfil-chain",
                "title": "Correlated Attack Chain: Credential Theft & Data Exfiltration",
                "severity": "critical",
                "description": "Correlated behavior: package accesses sensitive credentials/environment dotfiles and establishes outbound network connections.",
                "source": "behavior_correlation",
                "impact": "High risk of environment variable, token, or SSH key exfiltration to remote attacker servers.",
                "confidence": "high",
                "recommendation": "Rotate all secrets present in the developer environment immediately.",
                "rule_id": "attack-chain-exfiltration",
                "references": ["https://attack.mitre.org/tactics/TA0010/"]
            })

        # 3. Supply Chain Dropper: Typosquatting + Install Script
        if is_typosquatting and has_install_script:
            target = metadata.get("typosquatting_target", "popular package")
            correlated_findings.append({
                "id": "corr-typosquat-dropper",
                "title": "Correlated Threat: Typosquatting Dropper Campaign",
                "severity": "critical",
                "description": f"Package name closely mimics popular library '{target}' and executes automatic lifecycle scripts upon 'npm install'.",
                "source": "behavior_correlation",
                "impact": "Developers mistakenly installing this package are compromised automatically at build/install time.",
                "confidence": "confirmed",
                "recommendation": f"Uninstall immediately and verify package name spelling. You likely intended to install '{target}'.",
                "rule_id": "attack-chain-typosquat-dropper",
                "references": ["https://attack.mitre.org/tactics/TA0001/"]
            })

        # 4. Install-time Execution
        if has_install_script and (has_shell or has_network):
            correlated_findings.append({
                "id": "corr-install-time-network",
                "title": "Install-Time Network / Process Execution",
                "severity": "high",
                "description": "Lifecycle scripts (preinstall/postinstall) trigger network communication or shell execution during installation.",
                "source": "behavior_correlation",
                "impact": "Code execution occurs without requiring the application to import the library.",
                "confidence": "high",
                "recommendation": "Inspect package.json 'scripts' block to verify what binaries are executed during npm install.",
                "rule_id": "attack-chain-install-execution",
                "references": ["https://docs.npmjs.com/cli/v9/using-npm/scripts"]
            })

        return correlated_findings
