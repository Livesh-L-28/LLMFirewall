"""Offline dependency scanner, SBOM generation, and vulnerability provider abstraction."""

from abc import ABC, abstractmethod
import importlib.metadata
import json
import sys
from typing import Any, Dict, List, Optional, Set

from llmfirewall.core.models import Action, Finding, Severity, ThreatType
from llmfirewall.supply_chain.models import (
    DependencyArtifact,
    DependencyScope,
    DependencySourceType,
    VulnerabilityFinding,
)


class VulnerabilityProvider(ABC):
    """Abstract vulnerability intelligence provider interface."""

    @abstractmethod
    def lookup(self, package: str, version: str) -> List[VulnerabilityFinding]:
        """Lookup known vulnerabilities for package and version. Must not fail silently."""
        pass


class OfflineVulnerabilityProvider(VulnerabilityProvider):
    """Safe, default vulnerability provider that works completely offline with an optional local database."""

    def __init__(self, local_advisories: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> None:
        self.advisories = local_advisories or {}

    def lookup(self, package: str, version: str) -> List[VulnerabilityFinding]:
        pkg_key = package.lower().replace("-", "_")
        matches = self.advisories.get(pkg_key, [])
        findings = []
        for adv in matches:
            # Check affected version if present
            affected = adv.get("affected_versions", [])
            if not affected or version in affected:
                sev_str = str(adv.get("severity", "medium")).lower()
                try:
                    sev = Severity(sev_str)
                except ValueError:
                    sev = Severity.MEDIUM

                findings.append(
                    VulnerabilityFinding(
                        package=package,
                        version=version,
                        identifier=adv.get("id", "VULN-UNKNOWN"),
                        severity=sev,
                        summary=adv.get("summary", "Known vulnerability advisory."),
                        source="local_offline_db",
                        fixed_versions=adv.get("fixed_versions", []),
                    )
                )
        return findings


class DependencyScanner:
    """Discovers installed Python dependencies, parses direct vs transitive relations, and generates SBOMs."""

    def __init__(
        self,
        vulnerability_provider: Optional[VulnerabilityProvider] = None,
        allowed_packages: Optional[List[str]] = None,
        blocked_packages: Optional[List[str]] = None,
    ) -> None:
        self.vuln_provider = vulnerability_provider or OfflineVulnerabilityProvider()
        self.allowed_packages = {p.lower() for p in (allowed_packages or [])}
        self.blocked_packages = {p.lower() for p in (blocked_packages or [])}

    def scan_environment(self) -> List[DependencyArtifact]:
        """Scan current Python environment using standard library importlib.metadata (offline)."""
        artifacts: List[DependencyArtifact] = []

        try:
            dists = list(importlib.metadata.distributions())
        except Exception:
            return []

        # Find direct dependencies from packages that list requirements
        direct_packages: Set[str] = set()
        for dist in dists:
            try:
                requires = dist.requires
                if requires:
                    for req in requires:
                        pkg_req = req.split(";")[0].split("=")[0].split(">")[0].split("<")[0].strip()
                        if pkg_req:
                            direct_packages.add(pkg_req.lower())
            except Exception:
                continue

        for dist in dists:
            name = dist.metadata.get("Name", dist.name if hasattr(dist, "name") else "unknown")
            version = dist.version or "0.0.0"

            # Determine scope
            scope = DependencyScope.TRANSITIVE if name.lower() in direct_packages else DependencyScope.DIRECT

            # Determine source origin
            source = DependencySourceType.PYPI
            location_str = None
            try:
                # Check editable or local wheel installation
                if dist.origin and hasattr(dist.origin, "url"):
                    url = str(dist.origin.url)
                    if url.startswith("file:"):
                        source = DependencySourceType.LOCAL_WHEEL
                if hasattr(dist, "locate_file"):
                    location_str = str(dist.locate_file(""))
                    if "site-packages" not in location_str:
                        source = DependencySourceType.EDITABLE_INSTALL
            except Exception:
                pass

            artifacts.append(
                DependencyArtifact(
                    name=name,
                    version=version,
                    source=source,
                    scope=scope,
                    installed_location=location_str,
                )
            )

        artifacts.sort(key=lambda x: x.name.lower())
        return artifacts

    def evaluate_dependencies(
        self,
        dependencies: Optional[List[DependencyArtifact]] = None,
    ) -> List[Finding]:
        """Evaluate dependencies against policy (blocklists, unpinned constraints, vulnerabilities)."""
        deps = dependencies if dependencies is not None else self.scan_environment()
        findings: List[Finding] = []

        for dep in deps:
            name_lower = dep.name.lower()

            # 1. Denylist / Blocklist check
            if name_lower in self.blocked_packages:
                findings.append(
                    Finding(
                        detector_name="dependency_security",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=f"Dependency '{dep.name}' is explicitly blocked by policy.",
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        metadata={"violation": "DEPENDENCY_BLOCKED", "package": dep.name},
                    )
                )

            # 2. Allowlist check (if allowlist configured)
            if self.allowed_packages and name_lower not in self.allowed_packages:
                findings.append(
                    Finding(
                        detector_name="dependency_security",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=f"Dependency '{dep.name}' is not in allowed packages policy.",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        metadata={"violation": "DEPENDENCY_NOT_ALLOWED", "package": dep.name},
                    )
                )

            # 3. Vulnerability lookup
            vulns = self.vuln_provider.lookup(dep.name, dep.version)
            for v in vulns:
                findings.append(
                    Finding(
                        detector_name="dependency_vulnerability",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=(
                            f"Vulnerability {v.identifier} ({v.severity.value}) detected in "
                            f"{v.package}=={v.version}: {v.summary or 'No summary provided'}"
                        ),
                        severity=v.severity,
                        confidence=1.0,
                        metadata={
                            "violation": "VULNERABILITY_FOUND",
                            "package": v.package,
                            "version": v.version,
                            "cve": v.identifier,
                            "fixed_versions": v.fixed_versions,
                        },
                    )
                )

        return findings

    def generate_sbom(
        self,
        dependencies: Optional[List[DependencyArtifact]] = None,
        format_type: str = "cyclonedx",
    ) -> Dict[str, Any]:
        """Generate a standardized CycloneDX-compatible or normalized JSON SBOM without secrets.
        
        Args:
            dependencies: List of dependencies (defaults to environment scan).
            format_type: 'cyclonedx' or 'normalized'.
        """
        deps = dependencies if dependencies is not None else self.scan_environment()

        if format_type.lower() == "cyclonedx":
            components = []
            for d in deps:
                components.append({
                    "type": "library",
                    "name": d.name,
                    "version": d.version,
                    "scope": "required" if d.scope == DependencyScope.DIRECT else "optional",
                    "purl": f"pkg:pypi/{d.name}@{d.version}",
                    "properties": [
                        {"name": "source", "value": d.source.value},
                    ],
                })
            return {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "version": 1,
                "components": components,
            }

        # Normalized default
        return {
            "schema_version": "1",
            "format": "normalized",
            "dependencies": [
                {
                    "name": d.name,
                    "version": d.version,
                    "source": d.source.value,
                    "scope": d.scope.value,
                }
                for d in deps
            ],
        }
