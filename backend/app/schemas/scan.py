import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class FindingSchema(BaseModel):
    id: str
    title: str
    severity: str
    description: str
    source: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    matched_pattern: Optional[str] = None
    impact: Optional[str] = None
    confidence: Optional[str] = "high"
    recommendation: Optional[str] = None
    rule_id: Optional[str] = None
    references: List[str] = []

    model_config = ConfigDict(from_attributes=True)


class DependencySchema(BaseModel):
    id: str
    name: str
    version: str
    dep_type: str
    parent_name: Optional[str] = None
    dependency_path: Optional[str] = None
    risk_level: str
    findings_count: int = 0
    vulnerabilities: List[Dict[str, Any]] = []

    model_config = ConfigDict(from_attributes=True)


class PackageMetadataSchema(BaseModel):
    name: str
    version: str
    description: Optional[str] = None
    author: Optional[str] = None
    author_email: Optional[str] = None
    license: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    has_install_scripts: bool = False
    install_scripts_detail: Dict[str, Any] = {}
    is_typosquatting: bool = False
    typosquatting_target: Optional[str] = None
    is_unclaimed_or_disposable: bool = False
    has_binary: bool = False
    has_direct_url_deps: bool = False
    maintainers: List[Dict[str, Any]] = []

    model_config = ConfigDict(from_attributes=True)


class ScanCreateRequest(BaseModel):
    package_name: str
    version: Optional[str] = None
    is_demo: bool = False


class ScanResponse(BaseModel):
    id: str
    package_name: str
    version: Optional[str] = None
    scan_type: str
    status: str
    risk_score: float
    risk_level: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_findings: int
    summary: Optional[str] = None
    ai_explanation: Optional[str] = None
    ai_provider: Optional[str] = "deterministic"
    recommendations: List[str] = []
    score_breakdown: Dict[str, Any] = {}
    is_demo: bool = False
    error_message: Optional[str] = None
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None
    findings: List[FindingSchema] = []
    package_metadata: Optional[PackageMetadataSchema] = None
    dependencies: List[DependencySchema] = []

    model_config = ConfigDict(from_attributes=True)


class ScanSummaryResponse(BaseModel):
    id: str
    package_name: str
    version: Optional[str] = None
    scan_type: str
    status: str
    risk_score: float
    risk_level: str
    total_findings: int
    is_demo: bool
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None

    model_config = ConfigDict(from_attributes=True)


class DashboardOverviewResponse(BaseModel):
    total_scanned: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    clean_count: int
    total_vulnerabilities_found: int
    recent_scans: List[ScanSummaryResponse]
    risk_distribution: Dict[str, int]
