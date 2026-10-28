from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models import Scan
from backend.app.services.report_generator import ReportGeneratorService

router = APIRouter(prefix="/scans", tags=["Reports"])
report_service = ReportGeneratorService()


@router.get("/{scan_id}/export")
def export_scan_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|csv)$"),
    db: Session = Depends(get_db)
):
    """Download actual scan results as JSON or CSV."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings_list = []
    for f in scan.findings:
        findings_list.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "description": f.description,
            "source": f.source,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "code_snippet": f.code_snippet,
            "impact": f.impact,
            "confidence": f.confidence,
            "recommendation": f.recommendation,
            "rule_id": f.rule_id,
            "references": f.references or []
        })

    deps_list = []
    for d in scan.dependencies:
        deps_list.append({
            "name": d.name,
            "version": d.version,
            "dep_type": d.dep_type,
            "parent_name": d.parent_name,
            "dependency_path": d.dependency_path,
            "risk_level": d.risk_level,
            "findings_count": d.findings_count
        })

    scan_data = {
        "id": scan.id,
        "package_name": scan.package_name,
        "version": scan.version,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "total_findings": scan.total_findings,
        "summary": scan.summary,
        "ai_explanation": scan.ai_explanation,
        "ai_provider": scan.ai_provider,
        "recommendations": scan.recommendations or [],
        "score_breakdown": scan.score_breakdown or {},
        "created_at": str(scan.created_at),
        "completed_at": str(scan.completed_at) if scan.completed_at else None,
        "findings": findings_list,
        "dependencies": deps_list
    }

    safe_name = scan.package_name.replace("/", "-").replace("@", "")

    if format.lower() == "csv":
        csv_content = report_service.export_csv(scan_data)
        filename = f"npm-shield-report-{safe_name}-{scan.version or 'scan'}.csv"
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    # Default JSON
    json_content = report_service.export_json(scan_data)
    filename = f"npm-shield-report-{safe_name}-{scan.version or 'scan'}.json"
    return Response(
        content=json_content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
