import uuid
from sqlalchemy import Column, String, Integer, Boolean, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base


class PackageMetadata(Base):
    __tablename__ = "package_metadata"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    
    name = Column(String(255), nullable=False)
    version = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)
    author = Column(String(255), nullable=True)
    author_email = Column(String(255), nullable=True)
    license = Column(String(100), nullable=True)
    homepage = Column(String(500), nullable=True)
    repository = Column(String(500), nullable=True)
    tarball_url = Column(String(500), nullable=True)
    
    # Security heuristics in metadata
    has_install_scripts = Column(Boolean, default=False)
    install_scripts_detail = Column(JSON, default=dict)
    is_typosquatting = Column(Boolean, default=False)
    typosquatting_target = Column(String(255), nullable=True)
    is_unclaimed_or_disposable = Column(Boolean, default=False)
    has_binary = Column(Boolean, default=False)
    has_direct_url_deps = Column(Boolean, default=False)
    
    maintainers = Column(JSON, default=list)
    raw_info = Column(JSON, default=dict)

    scan = relationship("Scan", back_populates="package_metadata")
