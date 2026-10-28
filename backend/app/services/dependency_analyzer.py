import json
import logging
from typing import Dict, Any, List, Tuple, Set

logger = logging.getLogger("dependency_analyzer")


class DependencyAnalyzer:
    def parse_manifest(self, content_str: str, filename: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Parse package.json or package-lock.json.
        Returns:
            dependencies: List of dependency objects with name, version, dep_type, parent, path
            summary: metadata about the manifest
        """
        try:
            data = json.loads(content_str)
        except Exception as e:
            raise ValueError(f"Failed to parse JSON file {filename}: {str(e)}")

        is_lockfile = "lock" in filename.lower() or "shrinkwrap" in filename.lower() or "packages" in data or "lockfileVersion" in data

        dependencies = []
        name = data.get("name", "unnamed-project")
        version = data.get("version", "1.0.0")

        if is_lockfile:
            dependencies = self._parse_lockfile(data, name)
        else:
            dependencies = self._parse_package_json(data, name)

        summary = {
            "project_name": name,
            "project_version": version,
            "is_lockfile": is_lockfile,
            "lockfile_version": data.get("lockfileVersion", 1) if is_lockfile else None,
            "total_dependencies": len(dependencies),
            "direct_count": sum(1 for d in dependencies if d["dep_type"] in ["direct", "dev"]),
            "transitive_count": sum(1 for d in dependencies if d["dep_type"] == "transitive")
        }

        return dependencies, summary

    def _parse_package_json(self, data: Dict[str, Any], root_name: str) -> List[Dict[str, Any]]:
        dependencies = []
        
        # Production dependencies
        prod_deps = data.get("dependencies", {})
        if isinstance(prod_deps, dict):
            for dep_name, version_spec in prod_deps.items():
                dependencies.append({
                    "name": dep_name,
                    "version": str(version_spec).lstrip("^~="),
                    "dep_type": "direct",
                    "parent_name": root_name,
                    "dependency_path": f"{root_name} -> {dep_name}",
                    "risk_level": "low",
                    "findings_count": 0,
                    "vulnerabilities": []
                })

        # Dev dependencies
        dev_deps = data.get("devDependencies", {})
        if isinstance(dev_deps, dict):
            for dep_name, version_spec in dev_deps.items():
                dependencies.append({
                    "name": dep_name,
                    "version": str(version_spec).lstrip("^~="),
                    "dep_type": "dev",
                    "parent_name": root_name,
                    "dependency_path": f"{root_name} -> {dep_name} (dev)",
                    "risk_level": "low",
                    "findings_count": 0,
                    "vulnerabilities": []
                })

        return dependencies

    def _parse_lockfile(self, data: Dict[str, Any], root_name: str) -> List[Dict[str, Any]]:
        dependencies = []
        seen: Set[str] = set()

        # Modern lockfile (v2 and v3) have 'packages' map
        packages = data.get("packages", {})
        if packages:
            for pkg_path, info in packages.items():
                if not pkg_path:  # root package ""
                    continue
                
                # Format: "node_modules/foo" or "node_modules/foo/node_modules/bar"
                parts = pkg_path.split("node_modules/")
                parts = [p.rstrip("/") for p in parts if p]
                if not parts:
                    continue

                pkg_name = parts[-1]
                parent_name = parts[-2] if len(parts) > 1 else root_name
                path_str = f"{root_name} -> {' -> '.join(parts)}"

                version = info.get("version", "unknown")
                is_dev = info.get("dev", False)
                dep_type = "transitive" if len(parts) > 1 else ("dev" if is_dev else "direct")

                key = f"{pkg_name}@{version}"
                if key not in seen:
                    seen.add(key)
                    dependencies.append({
                        "name": pkg_name,
                        "version": version,
                        "dep_type": dep_type,
                        "parent_name": parent_name,
                        "dependency_path": path_str,
                        "risk_level": "low",
                        "findings_count": 0,
                        "vulnerabilities": []
                    })
            return dependencies

        # Legacy lockfile v1 has 'dependencies' object
        v1_deps = data.get("dependencies", {})
        self._traverse_v1_deps(v1_deps, root_name, [root_name], dependencies, seen)
        return dependencies

    def _traverse_v1_deps(self, deps_dict: Dict[str, Any], parent_name: str, path_chain: List[str], result: List[Dict[str, Any]], seen: Set[str]):
        if not isinstance(deps_dict, dict):
            return

        for dep_name, info in deps_dict.items():
            version = info.get("version", "unknown")
            is_dev = info.get("dev", False)
            current_chain = path_chain + [dep_name]
            dep_type = "direct" if len(current_chain) == 2 and not is_dev else ("dev" if is_dev else "transitive")

            key = f"{dep_name}@{version}"
            if key not in seen:
                seen.add(key)
                result.append({
                    "name": dep_name,
                    "version": version,
                    "dep_type": dep_type,
                    "parent_name": parent_name,
                    "dependency_path": " -> ".join(current_chain),
                    "risk_level": "low",
                    "findings_count": 0,
                    "vulnerabilities": []
                })

            sub_deps = info.get("dependencies", {})
            if sub_deps:
                self._traverse_v1_deps(sub_deps, dep_name, current_chain, result, seen)
