"""
luci_sky.session.http — rate-limited, retrying HTTP session manager.

Wraps requests.Session to provide:
- Per-request rate limiting with optional jitter
- Retry adapter (2 retries on 5xx)
- Proxy support
- Authentication (credential login or pre-supplied token)
- clone() for per-thread independent sessions
"""
from __future__ import annotations

import logging
import random
import threading
import time
from copy import deepcopy
from typing import Any, Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from luci_sky.config import Config
from luci_sky.models import Target

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Managed HTTP session with rate limiting, retries, proxy, and auth support.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._session: requests.Session = self._build_session()
        self._lock = threading.Lock()
        self._last_request_time: float = 0.0
        self.is_authenticated: bool = False
        self.auth_token: Optional[str] = None

    # ------------------------------------------------------------------
    # Session construction
    # ------------------------------------------------------------------

    def _build_session(self) -> requests.Session:
        session = requests.Session()

        # Retry adapter: 2 retries, backoff, on 5xx status codes
        retry = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "PUT"],
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=10,
            pool_maxsize=20,
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # Proxy
        if self._config.proxy:
            session.proxies = {
                "http": self._config.proxy,
                "https": self._config.proxy,
            }

        # User agent
        session.headers["User-Agent"] = (
            "Mozilla/5.0 (compatible; luci-redteam/1.0; security-scanner)"
        )

        return session

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _throttle(self) -> None:
        if self._config.delay_ms <= 0:
            return
        delay_s = self._config.delay_ms / 1000.0
        if self._config.jitter_ms > 0:
            delay_s += random.uniform(0, self._config.jitter_ms / 1000.0)
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < delay_s:
                time.sleep(delay_s - elapsed)
            self._last_request_time = time.monotonic()

    # ------------------------------------------------------------------
    # Core request method
    # ------------------------------------------------------------------

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self._throttle()
        kwargs.setdefault("timeout", self._config.timeout)
        kwargs.setdefault("verify", self._config.verify_tls)
        logger.debug("%s %s", method, url)
        return self._session.request(method, url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("PUT", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("HEAD", url, **kwargs)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self, target: Target) -> bool:
        """
        Attempt to authenticate against the target.

        Priority:
        1. Pre-supplied session_token → inject as sysauth cookie directly.
        2. Username/password → POST to login endpoint.
        3. Neither → return False immediately without any network call.
        """
        if self._config.session_token:
            self._session.cookies.set("sysauth", self._config.session_token, domain=target.host)
            self.auth_token = self._config.session_token
            self.is_authenticated = True
            return True

        if not self._config.username:
            return False

        login_url = f"{target.url}/cgi-bin/luci/;stok=/login"
        payload = {
            "luci_username": self._config.username,
            "luci_password": self._config.password or "",
        }
        try:
            resp = self._session.request(
                "POST",
                login_url,
                data=payload,
                timeout=self._config.timeout,
                verify=self._config.verify_tls,
            )
            if "sysauth" in resp.cookies:
                self.auth_token = resp.cookies.get("sysauth")
                self.is_authenticated = True
                return True
        except Exception as exc:
            logger.warning("Authentication failed: %s", exc)

        return False

    def logout(self, target: Target) -> None:
        """Best-effort logout — never raises."""
        try:
            logout_url = f"{target.url}/cgi-bin/luci/;stok=/logout"
            self._session.request(
                "GET",
                logout_url,
                timeout=self._config.timeout,
                verify=self._config.verify_tls,
            )
        except Exception:
            pass
        finally:
            self.is_authenticated = False
            self.auth_token = None

    # ------------------------------------------------------------------
    # Resource cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying requests.Session and release connection pool resources."""
        try:
            self._session.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Cloning
    # ------------------------------------------------------------------

    def clone(self) -> "SessionManager":
        """
        Return a new SessionManager with an independent connection pool
        but the same cookies (auth state shared).
        """
        cloned = SessionManager(self._config)
        # Copy cookies from the current session
        for cookie in self._session.cookies:
            cloned._session.cookies.set_cookie(cookie)
        cloned.is_authenticated = self.is_authenticated
        cloned.auth_token = self.auth_token
        return cloned
