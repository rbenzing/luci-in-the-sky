"""
luci_sky.scanner — ScanEngine orchestration.

Manages the complete scan lifecycle: target validation, authentication,
check dispatch via ThreadPoolExecutor, finding collection, and logout.
"""
from __future__ import annotations

import logging
import queue
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

import sys as _sys
from luci_sky.config import Config
from luci_sky.models import Finding, ScanMode, ScanResult, Severity, Target
from luci_sky.session.http import SessionManager
from luci_sky.checks import filtered_checks


def _get_filtered_checks(*args, **kwargs):
    """
    Indirection so patch("luci_sky.scanner.filtered_checks") works even after
    test_packaging.py reloads luci_sky.* modules mid-session.
    """
    scanner_mod = _sys.modules.get("luci_sky.scanner")
    fn = getattr(scanner_mod, "filtered_checks", filtered_checks) if scanner_mod else filtered_checks
    return fn(*args, **kwargs)


def _make_session_manager(config):
    """
    Indirection so patch("luci_sky.scanner.SessionManager") works even after
    test_packaging.py reloads luci_sky.* modules mid-session.
    """
    scanner_mod = _sys.modules.get("luci_sky.scanner")
    cls = getattr(scanner_mod, "SessionManager", SessionManager) if scanner_mod else SessionManager
    return cls(config)

logger = logging.getLogger(__name__)


class Scanner:
    """Orchestrates a full scan run."""

    def __init__(
        self,
        config: Config,
        progress_callback: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self._config = config
        self._progress_callback = progress_callback

    # ------------------------------------------------------------------
    # Target building
    # ------------------------------------------------------------------

    def _build_target(self, url: str) -> Target:
        """Parse a URL string into a Target descriptor."""
        parsed = urlparse(url)
        scheme = parsed.scheme or "https"
        host = parsed.hostname or url
        port = parsed.port or (443 if scheme == "https" else 80)
        # Strip path from base URL
        base_url = f"{scheme}://{host}"
        if port not in (80, 443):
            base_url = f"{scheme}://{host}:{port}"
        base_url = base_url.rstrip("/")
        return Target(
            url=base_url,
            host=host,
            port=port,
            scheme=scheme,
            detected_version=None,
            detected_luci_version=None,
            open_ports=[],
            accessible_paths=[],
            is_authenticated=False,
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_target(self, target: Target, session: SessionManager) -> None:
        """Raise RuntimeError if the target is unreachable."""
        try:
            session.head(target.url)
        except Exception as exc:
            raise RuntimeError(f"Target unreachable: {target.url}") from exc

    # ------------------------------------------------------------------
    # Main run
    # ------------------------------------------------------------------

    def run(self) -> ScanResult:
        """Execute a full scan and return ScanResult."""
        config = self._config
        target_url = config.target_url or ""

        session = _make_session_manager(config)
        target = self._build_target(target_url)

        started_at = datetime.utcnow()

        # Validate reachability
        self._validate_target(target, session)

        # Authenticate if credentials provided
        if config.username or config.session_token:
            auth_ok = session.authenticate(target)
            if auth_ok:
                target.is_authenticated = True

        # Gather checks — use _get_filtered_checks so the call respects any
        # patch("luci_sky.scanner.filtered_checks") applied by tests.
        checks = _get_filtered_checks(
            mode=config.mode,
            severity_threshold=config.severity_threshold,
            include_ids=getattr(config, "include_checks", []) or [],
            exclude_ids=getattr(config, "exclude_checks", []) or [],
            requires_auth=target.is_authenticated,
        )

        # Execute checks concurrently
        findings: List[Finding] = []
        checks_run = len(checks)
        checks_failed_counter = [0]
        lock = threading.Lock()

        def run_check(check) -> List[Finding]:
            check_id = check.__class__.id
            try:
                self._emit_progress({"status": "started", "check_id": check_id})
                thread_session = session.clone()
                result = check.run(target, thread_session, config)
                self._emit_progress({"status": "done", "check_id": check_id, "findings": len(result)})
                return result or []
            except Exception as exc:
                logger.warning("Check %s failed: %s", check_id, exc)
                with lock:
                    checks_failed_counter[0] += 1
                self._emit_progress({"status": "error", "check_id": check_id, "error": str(exc)})
                return []

        max_workers = max(1, config.threads)
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(run_check, c): c for c in checks}
            for fut in as_completed(futures):
                findings.extend(fut.result())

        # Sort findings: severity descending, then CVSS descending
        findings.sort(
            key=lambda f: (f.severity.numeric_rank, f.cvss_score),
            reverse=True,
        )

        # Logout (best effort)
        if target.is_authenticated:
            session.logout(target)

        # Release connection pool resources
        session.close()

        finished_at = datetime.utcnow()

        return ScanResult(
            target=target,
            findings=findings,
            scan_mode=config.mode,
            tool_version="1.0.0",
            started_at=started_at,
            finished_at=finished_at,
            checks_run=checks_run,
            checks_failed=checks_failed_counter[0],
        )

    def _emit_progress(self, event: dict) -> None:
        if self._progress_callback:
            try:
                self._progress_callback(event)
            except Exception:
                pass
