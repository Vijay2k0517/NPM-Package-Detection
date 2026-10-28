import datetime
import uuid
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON
from sqlalchemy.orm import relationship
from backend.app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    package_name = Column(String(255), nullable=False, index=True)
    version = Column(String(50), nullable=True)
    scan_type = Column(String(50), default="package")  # "package" or "project"
    status = Column(String(50), default="queued")      # "queued", "running", "completed", "failed"
    
    # Risk Assessment
    risk_score = Column(Float, default=0.0)             # 0 to 100
    risk_level = Column(String(50), default="low")      # "low", "medium", "high", "critical"
    
    # Findings counters
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    
    # Execution & Results
    summary = Column(Text, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    ai_provider = Column(String(50), default="deterministic")
    recommendations = Column(JSON, default=list)
    score_breakdown = Column(JSON, default=dict)
    
    # Meta
    is_demo = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    dependencies = relationship("Dependency", back_populates="scan", cascade="all, delete-orphan")
    package_metadata = relationship("PackageMetadata", back_populates="scan", uselist=False, cascade="all, delete-orphan")
