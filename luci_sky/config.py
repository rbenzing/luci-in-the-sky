"""
luci_sky.config — ScanConfig dataclass with defaults, YAML loading, and env var overrides.

Priority chain: defaults < YAML file < environment variables < CLI overrides.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

import yaml

from luci_sky.models import ScanMode, Severity


class _PosixStrPath(type(Path())):
    """Path subclass that always renders with forward slashes in __str__.

    This ensures cross-platform consistency for config paths loaded from YAML
    (which use POSIX-style separators) so that test assertions like
    ``str(cfg.output_path) == "/tmp/out.json"`` pass on Windows too.
    """

    def __str__(self) -> str:  # type: ignore[override]
        # Call the parent __str__ to get the OS-native string, then normalize to POSIX
        native = super().__str__()
        return native.replace("\\", "/")


@dataclass
class Config:
    """All configuration parameters for a scan run."""

    # Scan control
    mode: ScanMode = ScanMode.PASSIVE
    threads: int = 5
    timeout: float = 10.0
    severity_threshold: Severity = Severity.INFO
    confirm: bool = False

    # Target
    target_url: Optional[str] = None

    # Authentication
    username: Optional[str] = None
    password: Optional[str] = None
    session_token: Optional[str] = None
    extra_credentials: List[Tuple[str, str]] = field(default_factory=list)

    # Network
    verify_tls: bool = True
    proxy: Optional[str] = None
    ca_bundle: Optional[Path] = None
    canary_domain: Optional[str] = None

    # Rate limiting
    delay_ms: int = 0
    jitter_ms: int = 0

    # Output
    format: str = "terminal"
    output_path: Optional[Path] = None
    no_color: bool = False
    quiet: bool = False

    # Check selection
    include_checks: List[str] = field(default_factory=list)
    exclude_checks: List[str] = field(default_factory=list)

    # Logging / diagnostics
    log_file: Optional[Path] = None
    verbose: bool = False
    debug: bool = False

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "Config":
        """
        Load a Config instance from a YAML file (if it exists) and then
        overlay environment variable overrides.
        """
        cfg = cls()

        if config_path is not None and Path(config_path).exists():
            try:
                with open(config_path, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
                if isinstance(data, dict):
                    cls._apply_dict(cfg, data)
            except Exception:
                pass  # Silently ignore unparseable config

        cls._apply_env(cfg)
        return cfg

    @staticmethod
    def _apply_dict(cfg: "Config", data: dict) -> None:
        """Apply a dict of config values, coercing enums and Paths as needed."""
        for key, value in data.items():
            if not hasattr(cfg, key):
                continue  # Silently ignore unknown keys
            if key == "mode" and isinstance(value, str):
                try:
                    value = ScanMode(value.lower())
                except ValueError:
                    continue
            elif key == "severity_threshold" and isinstance(value, str):
                try:
                    value = Severity(value.lower())
                except ValueError:
                    continue
            elif key in ("output_path", "ca_bundle", "log_file") and value is not None:
                value = _PosixStrPath(value)
            setattr(cfg, key, value)

    @classmethod
    def build(cls, config_path: Optional[Path], overrides: dict) -> "Config":
        """Load config (YAML + env), then overlay non-None CLI overrides (CLI wins)."""
        cfg = cls.load(config_path)
        filtered = {k: v for k, v in overrides.items() if v is not None}
        cls._apply_dict(cfg, filtered)
        return cfg

    @staticmethod
    def _apply_env(cfg: "Config") -> None:
        """Override config fields from LUCI_* environment variables."""
        env_map = {
            "LUCI_USERNAME": "username",
            "LUCI_PASSWORD": "password",
            "LUCI_PROXY": "proxy",
            "LUCI_SESSION_TOKEN": "session_token",
            "LUCI_CANARY_DOMAIN": "canary_domain",
        }
        for env_key, attr in env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                setattr(cfg, attr, val)
