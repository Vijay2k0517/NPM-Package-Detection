import uuid
from sqlalchemy import Column, String, Integer, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    
    title = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)  # "critical", "high", "medium", "low"
    description = Column(Text, nullable=False)
    source = Column(String(50), nullable=False)    # "static_analysis", "vulnerability", "metadata", "behavior_correlation"
    
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    matched_pattern = Column(String(255), nullable=True)
    
    impact = Column(Text, nullable=True)
    confidence = Column(String(50), default="high") # "confirmed", "high", "medium", "low"
    recommendation = Column(Text, nullable=True)
    rule_id = Column(String(100), nullable=True)
    references = Column(JSON, default=list)

    scan = relationship("Scan", back_populates="findings")
