import pytest
from luci_sky.cve import storage
from luci_sky.cve.database import CVEDatabase


@pytest.fixture(autouse=True)
def _reset_cve_singleton():
    """Keep the CVEDatabase singleton from leaking a tmp-dir load into other modules."""
    CVEDatabase.reset()
    yield
    CVEDatabase.reset()


_DB = """
version: 2
updated: "2000-01-01"
source: "https://example/luci_cves.yml"
cves:
  - id: CVE-0000-0001
    title: t
    description: d
    cvss_score: 9.0
    cvss_vector: v
    severity: critical
    detection_method: version
    component: c
    remediation: r
    affected_versions: []
"""


def _fresh_db(tmp_path, monkeypatch, text):
    monkeypatch.setenv("LUCI_DATA_DIR", str(tmp_path))
    (tmp_path / "luci_cves.yml").write_text(text, encoding="utf-8")
    CVEDatabase.reset()
    return CVEDatabase()


def test_user_dir_takes_precedence(tmp_path, monkeypatch):
    db = _fresh_db(tmp_path, monkeypatch, _DB)
    assert db.db_version == 2
    assert any(e.cve_id == "CVE-0000-0001" for e in db._entries)


def test_is_stale_past_threshold(tmp_path, monkeypatch):
    db = _fresh_db(tmp_path, monkeypatch, _DB)
    assert db.is_stale(max_age_days=90) is True


def test_user_db_path_respects_env(tmp_path, monkeypatch):
    monkeypatch.setenv("LUCI_DATA_DIR", str(tmp_path))
    assert storage.user_db_path() == tmp_path / "luci_cves.yml"
