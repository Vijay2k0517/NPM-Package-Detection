import urllib.parse
from fastapi import APIRouter, HTTPException
from backend.app.services.npm_registry import NPMRegistryService

router = APIRouter(prefix="/packages", tags=["Packages"])
registry_service = NPMRegistryService()


@router.get("/{package_name:path}/metadata")
def get_package_metadata(package_name: str, version: str = "latest"):
    """Fetch live registry metadata for an NPM package."""
    decoded_name = urllib.parse.unquote(package_name)
    try:
        full_data, resolved_version, version_data = registry_service.get_package_info(decoded_name, version)
        analysis = registry_service.analyze_metadata(decoded_name, resolved_version, full_data, version_data)
        return {
            "name": decoded_name,
            "version": resolved_version,
            "metadata": analysis,
            "all_versions": list(full_data.get("versions", {}).keys())[-20:],
            "dist_tags": full_data.get("dist-tags", {})
        }
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
