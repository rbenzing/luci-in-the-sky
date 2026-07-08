"""luci_sky.audit — thread-safe JSONL audit logger for HTTP calls."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from luci_sky.sanitize import sanitize


class AuditLogger:
    """Append one sanitized JSONL record per HTTP call. No-op when log_file is None."""

    def __init__(self, log_file: Optional[Path] = None, debug: bool = False) -> None:
        self._debug = debug
        self._lock = threading.Lock()
        self._fh = None
        if log_file is not None:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(path, "a", encoding="utf-8")

    def record(self, method: str, url: str, status: int, elapsed_ms: float,
               req_bytes: int, resp_bytes: int, snippet: str = "",
               req_body: str = "", resp_body: str = "") -> None:
        if self._fh is None:
            return
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "url": url,
            "status": status,
            "elapsed_ms": round(elapsed_ms, 2),
            "req_bytes": req_bytes,
            "resp_bytes": resp_bytes,
            "snippet": sanitize(snippet, max_len=300),
        }
        if self._debug:
            rec["req_body"] = sanitize(req_body, max_len=4000)
            rec["resp_body"] = sanitize(resp_body, max_len=4000)
        line = json.dumps(rec, default=str)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                finally:
                    self._fh = None
