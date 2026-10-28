from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models import Dependency, Scan
from backend.app.schemas import DependencySchema

router = APIRouter(prefix="/scans", tags=["Dependencies"])


@router.get("/{scan_id}/dependencies", response_model=List[DependencySchema])
def get_scan_dependencies(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve dependencies associated with a project or package scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    
    deps = db.query(Dependency).filter(Dependency.scan_id == scan_id).all()
    return deps
