from backend.app.services.risk_scoring import RiskScoringEngine


def test_clean_package_scoring():
    engine = RiskScoringEngine()
    score, level, breakdown = engine.calculate_score([], [], [], {})
    assert score == 0.0
    assert level == "low"
    assert breakdown["raw_total"] == 0.0


def test_high_risk_malware_scoring():
    engine = RiskScoringEngine()
    static_findings = [
        {"severity": "critical", "rule_id": "threat-runtime-obfuscation-base64exec"},
        {"severity": "high", "rule_id": "process-spawn-shell"}
    ]
    correlated_findings = [
        {"severity": "critical", "rule_id": "attack-chain-defense-evasion"}
    ]
    metadata = {
        "has_install_scripts": True,
        "is_typosquatting": True
    }
    
    score, level, breakdown = engine.calculate_score([], static_findings, correlated_findings, metadata)
    assert score >= 70.0
    assert level in ["high", "critical"]
    assert "methodology_version" in breakdown
