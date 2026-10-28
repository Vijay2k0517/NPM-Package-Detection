import io
import csv
import json
from typing import Dict, Any


class ReportGeneratorService:
    def export_json(self, scan_data: Dict[str, Any]) -> str:
        """Export scan data as formatted JSON string."""
        return json.dumps(scan_data, indent=2, default=str)

    def export_csv(self, scan_data: Dict[str, Any]) -> str:
        """Export findings as CSV table."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "Scan ID", "Package Name", "Version", "Risk Score", "Risk Level",
            "Finding ID", "Severity", "Finding Title", "Source",
            "File Path", "Line Number", "Description", "Recommendation"
        ])

        scan_id = scan_data.get("id", "")
        pkg = scan_data.get("package_name", "")
        version = scan_data.get("version", "")
        score = scan_data.get("risk_score", 0)
        level = scan_data.get("risk_level", "low")

        findings = scan_data.get("findings", [])
        if not findings:
            writer.writerow([
                scan_id, pkg, version, score, level,
                "NONE", "CLEAN", "No findings detected", "N/A",
                "N/A", "N/A", "Clean package", "None"
            ])
        else:
            for f in findings:
                writer.writerow([
                    scan_id, pkg, version, score, level,
                    f.get("id", ""),
                    f.get("severity", ""),
                    f.get("title", ""),
                    f.get("source", ""),
                    f.get("file_path", ""),
                    f.get("line_number", ""),
                    f.get("description", ""),
                    f.get("recommendation", "")
                ])

        return output.getvalue()
