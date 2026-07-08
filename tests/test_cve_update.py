import pytest
from luci_sky.cve import storage
from luci_sky.cve.database import CVEDatabase
from luci_sky.cve.update import update_cve_db


@pytest.fixture(autouse=True)
def _reset_cve_singleton():
    CVEDatabase.reset()
    yield
    CVEDatabase.reset()


_GOOD = 'version: 3\nupdated: "2030-01-01"\ncves: []\n'
_BAD = "just a string, not a mapping"


def test_update_from_file_writes_user_db(tmp_path, monkeypatch):
    monkeypatch.setenv("LUCI_DATA_DIR", str(tmp_path))
    src = tmp_path / "src.yml"
    src.write_text(_GOOD, encoding="utf-8")
    out = update_cve_db(from_file=src)
    assert out == storage.user_db_path()
    assert out.read_text(encoding="utf-8").strip() == _GOOD.strip()


def test_update_rejects_malformed(tmp_path, monkeypatch):
    monkeypatch.setenv("LUCI_DATA_DIR", str(tmp_path))
    src = tmp_path / "bad.yml"
    src.write_text(_BAD, encoding="utf-8")
    with pytest.raises(ValueError):
        update_cve_db(from_file=src)
    assert not storage.user_db_path().exists()
