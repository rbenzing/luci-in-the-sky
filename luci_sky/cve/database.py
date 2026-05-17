"""
luci_sky.cve.database — CVEDatabase singleton that loads luci_cves.yml.

Provides CVEDatabase.match(version) -> list[CVEEntry] for version-based and
behavior-based CVE correlation.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, List, Optional

import yaml
from packaging.version import Version, InvalidVersion

logger = logging.getLogger(__name__)

_DB_PATH = Path(__file__).parent / "data" / "luci_cves.yml"


@dataclass
class CVEEntry:
    """A single CVE database entry."""

    cve_id: str
    title: str
    description: str
    cvss_score: float
    cvss_vector: str
    severity: str
    detection_method: str  # "version", "behavior", or "both"
    component: str
    remediation: str
    references: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


class CVEDatabase:
    """Singleton CVE database loaded from luci_cves.yml."""

    _instance: ClassVar[Optional["CVEDatabase"]] = None
    _loaded: ClassVar[bool] = False

    def __new__(cls) -> "CVEDatabase":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not CVEDatabase._loaded:
            self._entries: List[CVEEntry] = []
            self._load()
            CVEDatabase._loaded = True

    def _load(self) -> None:
        """Load and parse luci_cves.yml."""
        try:
            with open(_DB_PATH, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            raw_cves = data.get("cves", [])
            for raw in raw_cves:
                try:
                    entry = CVEEntry(
                        cve_id=raw.get("id", ""),
                        title=raw.get("title", ""),
                        description=str(raw.get("description", "")).strip(),
                        cvss_score=float(raw.get("cvss_score", 0.0)),
                        cvss_vector=raw.get("cvss_vector", ""),
                        severity=raw.get("severity", "medium"),
                        detection_method=raw.get("detection_method", "version"),
                        component=raw.get("component", ""),
                        remediation=str(raw.get("remediation", "")).strip(),
                        references=list(raw.get("references", [])),
                        affected_versions=list(raw.get("affected_versions", [])),
                        tags=list(raw.get("tags", [])),
                    )
                    self._entries.append(entry)
                except Exception as exc:
                    logger.warning("Failed to parse CVE entry: %s", exc)
        except Exception as exc:
            logger.error("Failed to load CVE database: %s", exc)
            self._entries = []

    def match(self, target_version: Optional[str]) -> List[CVEEntry]:
        """
        Return CVE entries applicable to *target_version*.

        - If target_version is None: return only entries with detection_method in
          ('behavior', 'both').
        - If target_version is an invalid version string: return all entries
          (conservative fallback, better false positive than miss).
        - Otherwise: return version-matched entries (behavior + version-matched version entries).
        Results are sorted by cvss_score descending.
        """
        if target_version is None:
            # Without a detected version, only return behavior/both entries that have
            # no affected_versions constraints (i.e. truly apply to all versions).
            matched = [
                e for e in self._entries
                if e.detection_method in ("behavior", "both") and not e.affected_versions
            ]
            return sorted(matched, key=lambda e: e.cvss_score, reverse=True)

        try:
            parsed_version = Version(target_version)
        except InvalidVersion:
            # Conservative: return all entries
            return sorted(self._entries, key=lambda e: e.cvss_score, reverse=True)

        matched = []
        for entry in self._entries:
            if self._version_matches(parsed_version, entry.affected_versions):
                matched.append(entry)

        return sorted(matched, key=lambda e: e.cvss_score, reverse=True)

    def _version_matches(self, version: Version, specs: List[str]) -> bool:
        """
        Check whether *version* satisfies ALL spec strings in *specs*.

        Each spec is a string like ">= 19.07.0" or "< 21.02.5".
        All specs must be satisfied (AND logic within an entry).
        An empty specs list means no version restriction (matches all).
        """
        if not specs:
            return True

        for spec_str in specs:
            spec_str = spec_str.strip()
            if not self._match_single_spec(version, spec_str):
                return False
        return True

    @staticmethod
    def _match_single_spec(version: Version, spec: str) -> bool:
        """Evaluate a single version comparison spec like '>= 19.07.0'."""
        for op in (">=", "<=", "!=", ">", "<", "=="):
            if spec.startswith(op):
                ver_str = spec[len(op):].strip()
                try:
                    target = Version(ver_str)
                except InvalidVersion:
                    return True  # Can't parse — assume matches
                if op == ">=":
                    return version >= target
                elif op == "<=":
                    return version <= target
                elif op == "!=":
                    return version != target
                elif op == ">":
                    return version > target
                elif op == "<":
                    return version < target
                elif op == "==":
                    return version == target
        # No operator found — treat as exact match
        try:
            return version == Version(spec)
        except InvalidVersion:
            return True
