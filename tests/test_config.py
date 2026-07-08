"""
Unit tests for luci_sky.config — ScanConfig validation, defaults, and load().

Tests will fail with ImportError until luci_sky/config.py is implemented.
Priority chain: defaults < YAML < environment < CLI.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from luci_sky.config import Config
from luci_sky.models import ScanMode, Severity


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------


class TestConfigDefaults:
    def test_default_config_has_passive_mode(self):
        """Default scan mode must be PASSIVE (read-only, safest)."""
        cfg = Config()
        assert cfg.mode == ScanMode.PASSIVE

    def test_default_config_threads_is_5(self):
        """Default thread count must be 5 per architecture specification."""
        cfg = Config()
        assert cfg.threads == 5

    def test_default_config_timeout_is_10(self):
        """Default per-request timeout must be 10.0 seconds."""
        cfg = Config()
        assert cfg.timeout == 10.0

    def test_default_config_format_is_terminal(self):
        """Default output format must be 'terminal'."""
        cfg = Config()
        assert cfg.format == "terminal"

    def test_default_config_severity_threshold_is_info(self):
        """Default severity threshold must be INFO (report everything)."""
        cfg = Config()
        assert cfg.severity_threshold == Severity.INFO

    def test_default_config_verify_tls_is_true(self):
        """TLS verification must be enabled by default."""
        cfg = Config()
        assert cfg.verify_tls is True

    def test_default_config_no_credentials(self):
        """No username or password should be set in the default config."""
        cfg = Config()
        assert cfg.username is None
        assert cfg.password is None

    def test_default_config_confirm_is_false(self):
        """Active-mode confirmation gate must default to False (require prompt)."""
        cfg = Config()
        assert cfg.confirm is False

    def test_default_config_delay_and_jitter_are_zero(self):
        """Rate-limiting delay and jitter must default to zero (no throttling)."""
        cfg = Config()
        assert cfg.delay_ms == 0
        assert cfg.jitter_ms == 0


# ---------------------------------------------------------------------------
# Config.load() — no file / non-existent path
# ---------------------------------------------------------------------------


class TestConfigLoad:
    def test_load_returns_config_when_no_file(self, tmp_path: Path):
        """Config.load() must return a default Config when the path does not exist."""
        nonexistent = tmp_path / "does_not_exist.yml"
        cfg = Config.load(nonexistent)
        assert isinstance(cfg, Config)
        assert cfg.mode == ScanMode.PASSIVE

    def test_load_from_yaml_overrides_mode(self, tmp_path: Path):
        """A YAML config with mode: active must override the default passive mode."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("mode: active\n")
        cfg = Config.load(config_file)
        assert cfg.mode == ScanMode.ACTIVE

    def test_load_from_yaml_overrides_threads(self, tmp_path: Path):
        """A YAML config with threads: 10 must override the default of 5."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("threads: 10\n")
        cfg = Config.load(config_file)
        assert cfg.threads == 10

    def test_load_from_yaml_coerces_severity(self, tmp_path: Path):
        """severity_threshold: high in YAML must load as Severity.HIGH enum."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("severity_threshold: high\n")
        cfg = Config.load(config_file)
        assert cfg.severity_threshold == Severity.HIGH

    def test_load_yaml_path_fields_become_path_objects(self, tmp_path: Path):
        """output_path and ca_bundle in YAML must be converted to pathlib.Path objects."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(f"output_path: /tmp/out.json\n")
        cfg = Config.load(config_file)
        assert isinstance(cfg.output_path, Path)
        assert str(cfg.output_path) == "/tmp/out.json"

    def test_load_from_yaml_full_mode(self, tmp_path: Path):
        """mode: full in YAML must set mode to ScanMode.FULL."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("mode: full\n")
        cfg = Config.load(config_file)
        assert cfg.mode == ScanMode.FULL


# ---------------------------------------------------------------------------
# Config._apply_env() — environment variable overrides
# ---------------------------------------------------------------------------


class TestConfigEnvVars:
    def test_env_var_username_override(self, tmp_path: Path):
        """LUCI_USERNAME env var must override username in the loaded Config."""
        os.environ["LUCI_USERNAME"] = "testuser"
        try:
            cfg = Config.load(tmp_path / "nonexistent.yml")
            assert cfg.username == "testuser"
        finally:
            del os.environ["LUCI_USERNAME"]

    def test_env_var_password_override(self, tmp_path: Path):
        """LUCI_PASSWORD env var must override password in the loaded Config."""
        os.environ["LUCI_PASSWORD"] = "s3cr3t"
        try:
            cfg = Config.load(tmp_path / "nonexistent.yml")
            assert cfg.password == "s3cr3t"
        finally:
            del os.environ["LUCI_PASSWORD"]

    def test_env_var_proxy_override(self, tmp_path: Path):
        """LUCI_PROXY env var must set the proxy field in the loaded Config."""
        os.environ["LUCI_PROXY"] = "http://127.0.0.1:8080"
        try:
            cfg = Config.load(tmp_path / "nonexistent.yml")
            assert cfg.proxy == "http://127.0.0.1:8080"
        finally:
            del os.environ["LUCI_PROXY"]

    def test_env_var_session_token_override(self, tmp_path: Path):
        """LUCI_SESSION_TOKEN env var must set session_token in the loaded Config."""
        os.environ["LUCI_SESSION_TOKEN"] = "abc123tok"
        try:
            cfg = Config.load(tmp_path / "nonexistent.yml")
            assert cfg.session_token == "abc123tok"
        finally:
            del os.environ["LUCI_SESSION_TOKEN"]

    def test_env_var_canary_domain_override(self, tmp_path: Path):
        """LUCI_CANARY_DOMAIN env var must set canary_domain in the loaded Config."""
        os.environ["LUCI_CANARY_DOMAIN"] = "oob.example.com"
        try:
            cfg = Config.load(tmp_path / "nonexistent.yml")
            assert cfg.canary_domain == "oob.example.com"
        finally:
            del os.environ["LUCI_CANARY_DOMAIN"]


# ---------------------------------------------------------------------------
# Config._apply_dict() — edge cases
# ---------------------------------------------------------------------------


class TestConfigApplyDict:
    def test_apply_dict_ignores_unknown_keys(self):
        """_apply_dict must silently ignore keys that do not exist on Config."""
        cfg = Config()
        original_mode = cfg.mode
        Config._apply_dict(cfg, {"nonexistent_key": "value", "another_bad_key": 42})
        # No exception raised and existing fields unchanged
        assert cfg.mode == original_mode

    def test_apply_dict_coerces_mode_string(self):
        """_apply_dict must convert the mode string 'active' to ScanMode.ACTIVE."""
        cfg = Config()
        Config._apply_dict(cfg, {"mode": "active"})
        assert cfg.mode == ScanMode.ACTIVE

    def test_apply_dict_coerces_severity_string(self):
        """_apply_dict must convert severity_threshold string to Severity enum."""
        cfg = Config()
        Config._apply_dict(cfg, {"severity_threshold": "medium"})
        assert cfg.severity_threshold == Severity.MEDIUM


def test_config_has_new_fields():
    cfg = Config()
    assert cfg.include_checks == []
    assert cfg.exclude_checks == []
    assert cfg.log_file is None
    assert cfg.verbose is False
    assert cfg.debug is False


def test_build_cli_overrides_win_over_yaml(tmp_path):
    cf = tmp_path / "c.yml"
    cf.write_text("mode: active\nthreads: 3\n")
    cfg = Config.build(cf, {"threads": 9, "mode": None})
    assert cfg.threads == 9          # CLI wins
    assert cfg.mode == ScanMode.ACTIVE  # None override ignored -> YAML value kept


def test_build_none_overrides_are_ignored(tmp_path):
    cfg = Config.build(None, {"severity_threshold": None})
    assert cfg.severity_threshold == Severity.INFO  # default preserved


def test_build_coerces_string_overrides():
    cfg = Config.build(None, {"mode": "full", "severity_threshold": "high"})
    assert cfg.mode == ScanMode.FULL
    assert cfg.severity_threshold == Severity.HIGH
