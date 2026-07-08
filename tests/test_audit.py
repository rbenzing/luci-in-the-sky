import json
from luci_sky.audit import AuditLogger


def test_record_writes_jsonl_line(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLogger(log_file=p)
    log.record("GET", "https://h/x", 200, 12.5, 0, 34, snippet="hello")
    log.close()
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["method"] == "GET" and rec["status"] == 200 and rec["snippet"] == "hello"


def test_record_sanitizes_snippet(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLogger(log_file=p)
    log.record("POST", "https://h/login", 200, 1.0, 0, 0,
               snippet="luci_password=hunter2")
    log.close()
    assert "hunter2" not in p.read_text(encoding="utf-8")


def test_bodies_only_in_debug(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLogger(log_file=p, debug=False)
    log.record("GET", "https://h", 200, 1.0, 0, 3, resp_body="abc")
    log.close()
    rec = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
    assert "resp_body" not in rec


def test_none_log_file_is_noop():
    log = AuditLogger(log_file=None)
    log.record("GET", "https://h", 200, 1.0, 0, 0)  # must not raise
    log.close()
