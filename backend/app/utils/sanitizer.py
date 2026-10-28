"""
Sanitization and safety utilities for NPM Shield AI.
"""
import re
from pathlib import Path


def sanitize_filename(filename: str) -> str:
    """Sanitize uploaded filenames against path traversal."""
    cleaned = Path(filename).name
    # Strip any dangerous characters
    cleaned = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', cleaned)
    return cleaned or "unnamed_manifest.json"


def sanitize_package_name(pkg: str) -> str:
    """Trim and format package names safely."""
    return pkg.strip()


def truncate_snippet(code: str, max_lines: int = 10, max_chars: int = 500) -> str:
    """Safely truncate large code snippets for reporting."""
    lines = code.splitlines()[:max_lines]
    snippet = "\n".join(lines)
    if len(snippet) > max_chars:
        snippet = snippet[:max_chars] + "... [truncated]"
    return snippet
