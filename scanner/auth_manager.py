"""
OBSERVER — Pre-Scan Authentication Manager
Handles authenticated session setup before crawling begins.

Supports:
  - Django-style login forms (csrftoken cookie + csrfmiddlewaretoken hidden field)
  - Generic form-based login (POST with username/password)
  - CSRF token extraction from cookies and HTML forms
  - Automatic X-CSRFToken header injection for POST requests
"""
import re
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


class AuthManager:
    """
    Manages pre-scan authentication and CSRF token handling.

    Usage:
        auth = AuthManager(session, timeout=10)
        success = auth.login(login_url, username, password, log_callback=...)
        # session is now authenticated
        headers = auth.prepare_post_headers(url)  # adds X-CSRFToken if available
    """

    # Common username field names used by login forms
    _USERNAME_FIELDS = {"username", "email", "user", "login", "identifier", "mail"}
    # Common password field names
    _PASSWORD_FIELDS = {"password", "passwd", "pass", "pwd", "secret"}

    def __init__(self, session: requests.Session, timeout: int = 10):
        self.session = session
        self.timeout = timeout
        self._authenticated = False

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def login(
        self,
        login_url: str,
        username: str,
        password: str,
        log_callback=None,
    ) -> bool:
        """
        Attempt to authenticate against `login_url` using form-based login.

        Steps:
          1. GET the login page to obtain the CSRF token (cookie + hidden field).
          2. Build POST payload from discovered form fields.
          3. POST credentials with CSRF protection included.
          4. Verify success by checking for absence of login form in response.

        Returns True on success, False on failure.
        The underlying `session` retains cookies for subsequent requests.
        """
        def _log(level: str, msg: str):
            if log_callback:
                log_callback(level, f"[AuthManager] {msg}")

        _log("INFO", f"Initiating pre-scan authentication against {login_url}")

        # --- Step 1: GET the login page ---
        try:
            resp = self.session.get(
                login_url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
        except Exception as exc:
            _log("ERROR", f"Failed to reach login URL: {exc}")
            return False

        if resp.status_code >= 400:
            _log("ERROR", f"Login page returned HTTP {resp.status_code}")
            return False

        # --- Step 2: Extract CSRF token and form field names ---
        csrf_token = self._extract_csrf_token(resp)
        username_field, password_field, extra_fields = self._discover_form_fields(resp, login_url)

        _log("DEBUG", f"Detected form fields — user: '{username_field}', pass: '{password_field}'")
        if csrf_token:
            _log("DEBUG", f"CSRF token found: {csrf_token[:12]}…")
        else:
            _log("DEBUG", "No CSRF token detected — proceeding without it")

        # --- Step 3: Build POST payload ---
        payload = {**extra_fields}
        if username_field:
            payload[username_field] = username
        else:
            # Fallback: try common field names
            payload["username"] = username

        if password_field:
            payload[password_field] = password
        else:
            payload["password"] = password

        if csrf_token:
            payload["csrfmiddlewaretoken"] = csrf_token

        # --- Step 4: POST credentials ---
        post_headers = {"Referer": login_url}
        if csrf_token:
            post_headers["X-CSRFToken"] = csrf_token

        try:
            post_resp = self.session.post(
                login_url,
                data=payload,
                headers=post_headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
        except Exception as exc:
            _log("ERROR", f"POST to login URL failed: {exc}")
            return False

        # --- Step 5: Verify success ---
        success = self._verify_login_success(post_resp, login_url)
        if success:
            self._authenticated = True
            _log("INFO", "Authentication successful — session cookies retained for scan")
        else:
            _log("WARNING",
                 "Authentication failed (credentials rejected or unexpected response). "
                 "Scan will continue on public scope only.")

        return success

    def get_csrf_token(self, url: str) -> str | None:
        """
        Return the CSRF token applicable to `url`.

        Checks, in order:
          1. Session cookie named 'csrftoken' (Django standard).
          2. Any cookie containing 'csrf' in its name.
        """
        parsed = urlparse(url)
        domain = parsed.netloc

        # Walk cookies in the session jar
        for cookie in self.session.cookies:
            if cookie.name.lower() == "csrftoken":
                return cookie.value
            if "csrf" in cookie.name.lower():
                return cookie.value

        return None

    def prepare_post_headers(self, url: str) -> dict:
        """
        Build extra headers to include in a POST/PUT/DELETE request to `url`.
        Adds X-CSRFToken if a CSRF token is available in the session.
        """
        headers: dict = {}
        token = self.get_csrf_token(url)
        if token:
            headers["X-CSRFToken"] = token
        return headers

    # ──────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_csrf_token(self, resp: requests.Response) -> str | None:
        """
        Extract CSRF token from response: first from hidden form field,
        then from cookies.
        """
        # 1. Hidden field csrfmiddlewaretoken in HTML
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            field = soup.find("input", attrs={"name": "csrfmiddlewaretoken"})
            if field and field.get("value"):
                return field["value"]
        except Exception:
            pass

        # 2. Cookie named csrftoken (set after GET)
        for cookie in self.session.cookies:
            if cookie.name.lower() == "csrftoken":
                return cookie.value
            if "csrf" in cookie.name.lower():
                return cookie.value

        return None

    def _discover_form_fields(
        self,
        resp: requests.Response,
        login_url: str,
    ) -> tuple[str | None, str | None, dict]:
        """
        Parse the login page HTML to discover:
          - The username/email input field name
          - The password input field name
          - Any other non-CSRF hidden fields (e.g. 'next', 'remember_me')

        Returns (username_field_name, password_field_name, extra_hidden_fields).
        """
        username_field: str | None = None
        password_field: str | None = None
        extra_fields: dict = {}

        try:
            soup = BeautifulSoup(resp.text, "html.parser")

            # Find the form that posts to the login URL (or any form)
            forms = soup.find_all("form")
            target_form = None
            for form in forms:
                action = form.get("action", "")
                if not action or login_url.endswith(action) or action in login_url:
                    target_form = form
                    break
            if not target_form and forms:
                target_form = forms[0]

            if not target_form:
                return None, None, {}

            for inp in target_form.find_all("input"):
                name = inp.get("name", "").lower()
                inp_type = inp.get("type", "text").lower()
                raw_name = inp.get("name", "")

                if not name:
                    continue

                if inp_type == "hidden":
                    if "csrf" not in name:
                        extra_fields[raw_name] = inp.get("value", "")
                elif inp_type == "password":
                    password_field = raw_name
                elif inp_type in ("text", "email", "tel"):
                    if name in self._USERNAME_FIELDS:
                        username_field = raw_name
                    elif username_field is None:
                        # Heuristic: first non-password text field
                        username_field = raw_name

        except Exception:
            pass

        return username_field, password_field, extra_fields

    def _verify_login_success(
        self, resp: requests.Response, login_url: str
    ) -> bool:
        """
        Heuristic verification that login succeeded:
          - Final URL is different from login URL (redirect after POST)
          - Response does NOT still contain a login/password form
          - HTTP status is not 4xx

        All three criteria together; any single pass counts as probable success.
        """
        if resp.status_code >= 400:
            return False

        final_url = resp.url
        redirected = final_url.rstrip("/") != login_url.rstrip("/")

        # Check if login form still present in response
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            has_password_field = bool(soup.find("input", attrs={"type": "password"}))
        except Exception:
            has_password_field = False

        # Also check for common error indicators
        error_patterns = [
            r"invalid (username|password|credentials)",
            r"incorrect (username|password|credentials)",
            r"login failed",
            r"authentication failed",
            r"wrong (password|credentials)",
        ]
        body_lower = resp.text.lower()
        has_error_message = any(
            re.search(pat, body_lower) for pat in error_patterns
        )

        if has_error_message:
            return False
        if redirected and not has_password_field:
            return True
        if not has_password_field:
            return True

        return False
