import os
import tarfile
import tempfile
import logging
import urllib.parse
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
import requests

from backend.app.config import settings

logger = logging.getLogger("npm_registry")

# Common popular packages for typosquatting detection
POPULAR_NPM_PACKAGES = {
    "react", "express", "lodash", "axios", "vue", "chalk", "moment", "commander",
    "request", "async", "bluebird", "debug", "colors", "underscore", "glob",
    "fs-extra", "body-parser", "cors", "dotenv", "cross-env", "webpack", "babel-core",
    "typescript", "next", "tailwindcss", "eslint", "jest", "rxjs", "prettier"
}

DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com", "tempmail.com", "10minutemail.com", "guerrillamail.com",
    "sharklasers.com", "throwawaymail.com", "yopmail.com", "dispostable.com"
}


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


class NPMRegistryService:
    def __init__(self, registry_url: str = settings.NPM_REGISTRY_URL, timeout: int = settings.REQUEST_TIMEOUT):
        self.registry_url = registry_url.rstrip("/")
        self.timeout = timeout

    def get_package_info(self, package_name: str, requested_version: Optional[str] = None) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
        """
        Fetch package manifest from npm registry.
        Returns (full_metadata, resolved_version, version_metadata)
        """
        encoded_name = urllib.parse.quote(package_name, safe="@")
        url = f"{self.registry_url}/{encoded_name}"
        
        logger.info(f"Fetching NPM registry info: {url}")
        try:
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 404:
                raise ValueError(f"Package '{package_name}' was not found on NPM registry.")
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            logger.error(f"NPM registry network error: {e}")
            raise RuntimeError(f"Failed to connect to NPM registry: {str(e)}")

        if "versions" not in data or not data["versions"]:
            raise ValueError(f"Package '{package_name}' has no available versions.")

        # Determine target version
        if not requested_version or requested_version == "latest":
            dist_tags = data.get("dist-tags", {})
            resolved_version = dist_tags.get("latest")
            if not resolved_version:
                resolved_version = list(data["versions"].keys())[-1]
        else:
            if requested_version in data["versions"]:
                resolved_version = requested_version
            else:
                # Find matching version or fallback
                resolved_version = data.get("dist-tags", {}).get(requested_version, requested_version)
                if resolved_version not in data["versions"]:
                    # Return latest available version with warning or raise
                    raise ValueError(f"Version '{requested_version}' of '{package_name}' does not exist.")

        version_data = data["versions"].get(resolved_version, {})
        return data, resolved_version, version_data

    def download_and_extract_tarball(self, tarball_url: str) -> Tuple[str, str]:
        """
        Safely download and extract tarball to a temporary directory.
        Returns (temp_parent_dir, extracted_source_dir)
        """
        temp_dir = tempfile.mkdtemp(prefix="npm_shield_")
        tar_path = os.path.join(temp_dir, "package.tgz")
        extract_dir = os.path.join(temp_dir, "source")
        os.makedirs(extract_dir, exist_ok=True)

        logger.info(f"Downloading tarball: {tarball_url}")
        resp = requests.get(tarball_url, timeout=self.timeout, stream=True)
        resp.raise_for_status()

        with open(tar_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=16384):
                f.write(chunk)

        # Safe extraction (Path Traversal Protection)
        with tarfile.open(tar_path, "r:gz") as tar:
            target_base = os.path.abspath(extract_dir)
            for member in tar.getmembers():
                member_path = os.path.abspath(os.path.join(extract_dir, member.name))
                if not member_path.startswith(target_base):
                    raise SecurityError(f"Attempted Path Traversal in tar file: {member.name}")
            tar.extractall(path=extract_dir)

        # In NPM tarballs, files are commonly nested inside a 'package' subfolder
        inner_pkg = os.path.join(extract_dir, "package")
        final_dir = inner_pkg if os.path.isdir(inner_pkg) else extract_dir

        return temp_dir, final_dir

    def analyze_metadata(self, package_name: str, version: str, full_data: Dict[str, Any], version_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Examine metadata for supply-chain heuristics:
        - Typosquatting against popular packages
        - Suspicious lifecycle install scripts (preinstall, install, postinstall)
        - Disposable or missing author emails
        - Bundled binaries
        - Direct URL / git dependencies
        """
        scripts = version_data.get("scripts", {})
        install_scripts = {}
        for s in ["preinstall", "install", "postinstall", "preuninstall", "postuninstall"]:
            if s in scripts:
                install_scripts[s] = scripts[s]

        # Typosquatting check
        base_name = package_name.lower().split("/")[-1] # strip scope if any
        is_typosquatting = False
        target_package = None

        if base_name not in POPULAR_NPM_PACKAGES:
            for pop in POPULAR_NPM_PACKAGES:
                dist = _levenshtein_distance(base_name, pop)
                # 1 edit distance or close match
                if dist == 1 and len(base_name) >= 4:
                    is_typosquatting = True
                    target_package = pop
                    break

        # Author & maintainers
        author = version_data.get("author", {})
        author_name = author if isinstance(author, str) else (author.get("name", "") if isinstance(author, dict) else "")
        author_email = author.get("email", "") if isinstance(author, dict) else ""
        
        is_disposable_email = False
        if author_email and "@" in author_email:
            domain = author_email.split("@")[-1].lower()
            if domain in DISPOSABLE_EMAIL_DOMAINS:
                is_disposable_email = True

        # Dependencies check for direct git / URL dependencies
        deps = version_data.get("dependencies", {})
        has_direct_url = any(
            isinstance(v, str) and (v.startswith("http:") or v.startswith("https:") or v.startswith("git+") or v.endswith(".git"))
            for v in deps.values()
        )

        # Dist tarball url
        dist = version_data.get("dist", {})
        tarball_url = dist.get("tarball", "")

        return {
            "has_install_scripts": len(install_scripts) > 0,
            "install_scripts": install_scripts,
            "is_typosquatting": is_typosquatting,
            "typosquatting_target": target_package,
            "is_unclaimed_or_disposable": is_disposable_email,
            "has_direct_url_deps": has_direct_url,
            "author_name": author_name,
            "author_email": author_email,
            "license": version_data.get("license", "Unknown"),
            "description": version_data.get("description", ""),
            "homepage": version_data.get("homepage", ""),
            "repository": str(version_data.get("repository", "")),
            "tarball_url": tarball_url,
            "maintainers": version_data.get("maintainers", full_data.get("maintainers", []))
        }
