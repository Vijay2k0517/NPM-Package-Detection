import sys
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models import Scan, Finding
from backend.app.schemas import DashboardOverviewResponse
from backend.app.config import settings

router = APIRouter(tags=["Overview"])


@router.get("/overview", response_model=DashboardOverviewResponse)
def get_overview_metrics(db: Session = Depends(get_db)):
    """Aggregate actual security scan metrics for the Security Overview dashboard."""
    all_scans = db.query(Scan).order_by(desc(Scan.created_at)).all()
    
    total = len(all_scans)
    high_count = sum(1 for s in all_scans if s.risk_level in ["critical", "high"])
    med_count = sum(1 for s in all_scans if s.risk_level == "medium")
    low_count = sum(1 for s in all_scans if s.risk_level == "low")
    clean_count = sum(1 for s in all_scans if s.risk_score == 0)

    # Known vulnerabilities count from findings
    total_vulns = db.query(Finding).filter(Finding.source == "vulnerability").count()

    risk_dist = {
        "critical": sum(1 for s in all_scans if s.risk_level == "critical"),
        "high": sum(1 for s in all_scans if s.risk_level == "high"),
        "medium": med_count,
        "low": low_count
    }

    recent = all_scans[:8]

    return {
        "total_scanned": total,
        "high_risk_count": high_count,
        "medium_risk_count": med_count,
        "low_risk_count": low_count,
        "clean_count": clean_count,
        "total_vulnerabilities_found": total_vulns,
        "recent_scans": recent,
        "risk_distribution": risk_dist
    }


@router.get("/health")
def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "service": "NPM Shield AI",
        "version": settings.APP_VERSION,
        "python_version": sys.version.split()[0],
        "database": "SQLite (Active)",
        "dynamic_analysis": "Unsupported on host OS (Safe static mode active)"
    }


@router.get("/settings")
def get_app_settings():
    """Retrieve functional application configuration information."""
    ai_status = "Enabled (Gemini)" if settings.GEMINI_API_KEY else ("Enabled (OpenAI)" if settings.OPENAI_API_KEY else "Deterministic Expert Security Engine (Active)")
    
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "backend_status": "Connected & Operational",
        "database": "Local SQLite (npm_shield.db)",
        "ai_provider": ai_status,
        "supported_scans": ["NPM Package (Single)", "package.json (Manifest)", "package-lock.json (Lockfile v1, v2, v3)"],
        "osv_advisory_source": "OSV.dev (Open Source Vulnerabilities API)",
        "dynamic_analysis_status": "Disabled (Requires dedicated container runtime)",
        "demo_mode_available": settings.DEMO_MODE_ENABLED
    }
