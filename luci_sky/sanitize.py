"""luci_sky.sanitize — shared secret-masking for evidence and audit logs."""
from __future__ import annotations

import re

_SYSAUTH_RE = re.compile(r"(sysauth(?:_\w+)?=)([A-Za-z0-9]{8})([A-Za-z0-9]+)")
_PASSWORD_RE = re.compile(r"(?i)((?:luci_)?password=)[^\s&\"']+")
_QUOTED_PW_RE = re.compile(
    r"""(?i)(['"](?:luci_)?password['"]\s*:\s*)(['"])[^'"]*(['"])"""
)
_AUTH_RE = re.compile(r"(Authorization:\s*\w+\s+)\S+", re.IGNORECASE)


def sanitize(text: str, max_len: int = 2000) -> str:
    """Mask sysauth cookies, password fields, and Authorization tokens, then truncate."""
    text = _SYSAUTH_RE.sub(r"\1\2***", text)
    text = _PASSWORD_RE.sub(r"\1***", text)
    text = _QUOTED_PW_RE.sub(r"\1\2***\3", text)
    text = _AUTH_RE.sub(r"\1***", text)
    return text[:max_len]
