import uuid
from sqlalchemy import Column, String, Integer, JSON, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base


class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    
    name = Column(String(255), nullable=False)
    version = Column(String(100), nullable=False)
    dep_type = Column(String(50), default="direct")   # "direct", "dev", "transitive"
    parent_name = Column(String(255), nullable=True)
    dependency_path = Column(String(500), nullable=True) # e.g. "my-app -> lodash -> sub-dep"
    
    risk_level = Column(String(50), default="low")    # "low", "medium", "high", "critical"
    findings_count = Column(Integer, default=0)
    vulnerabilities = Column(JSON, default=list)

    scan = relationship("Scan", back_populates="dependencies")
