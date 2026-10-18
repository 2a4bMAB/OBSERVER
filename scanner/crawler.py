"""
OBSERVER — Web Crawler / Target Discovery Module
Crawls a target website within scope to discover:
  - Accessible URLs & endpoints
  - HTML Forms, input fields, and parameters
  - URL Query parameters
  - Static assets and scripts
"""
import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import requests


class CrawledForm:
    """Represents a discovered HTML form."""
    def __init__(self, action: str, method: str, inputs: list[dict]):
        self.action = action
        self.method = method.upper()
        self.inputs = inputs  # list of {'name': str, 'type': str, 'value': str}

    def __repr__(self):
        return f"<CrawledForm method={self.method} action={self.action} inputs={len(self.inputs)}>"


class CrawlResult:
    """Aggregated result of crawling a target."""
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.discovered_urls: set[str] = set()
        self.forms: list[CrawledForm] = []
        self.parameters: dict[str, set[str]] = {}  # url -> set of param names
        self.scripts: set[str] = set()
        self.stylesheets: set[str] = set()
        self.responses: dict[str, requests.Response] = {}  # url -> Response cache


class WebCrawler:
    """
    Crawls web applications within domain scope.
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 50,
        timeout: int = 10,
        user_agent: str = "OBSERVER-Security-Audit/1.0",
        headers: dict | None = None,
        session: requests.Session | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(self.base_url)
        self.base_domain = self.parsed_base.netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout

        # Use an externally provided session (e.g. authenticated) or create a new one.
        # This allows the crawler to access pages behind authentication without
        # losing session cookies obtained during the pre-scan login phase.
        self.session = session if session is not None else requests.Session()
        default_headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if headers:
            default_headers.update(headers)
        self.session.headers.update(default_headers)

    def is_in_scope(self, url: str) -> bool:
        """Ensure URL belongs to the same target domain."""
        parsed = urlparse(url)
        if not parsed.netloc:
            return True
        return parsed.netloc.lower() == self.base_domain.lower()

    def normalize_url(self, url: str) -> str:
        """Strip URL fragments and normalize."""
        parsed = urlparse(url)
        # Remove fragment
        return parsed._replace(fragment="").geturl()

    def crawl(self, log_callback=None) -> CrawlResult:
        """
        Execute crawling starting from base_url.
        `log_callback(level, message)` is called to report progress.
        """
        result = CrawlResult(self.base_url)
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(self.base_url, 0)]  # (url, depth)

        if log_callback:
            log_callback("INFO", f"[Crawler] Starting crawl on {self.base_url} (max depth: {self.max_depth}, max pages: {self.max_pages})")

        while queue and len(visited) < self.max_pages:
            current_url, depth = queue.pop(0)
            current_url = self.normalize_url(current_url)

            if current_url in visited:
                continue

            visited.add(current_url)
            result.discovered_urls.add(current_url)

            # Record query parameters
            parsed = urlparse(current_url)
            if parsed.query:
                params = set(parse_qs(parsed.query).keys())
                if params:
                    result.parameters[current_url] = params

            if log_callback:
                log_callback("DEBUG", f"[Crawler] Fetching ({len(visited)}/{self.max_pages}): {current_url}")

            try:
                resp = self.session.get(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False  # Allow auditing sites with self-signed certs
                )
                result.responses[current_url] = resp
            except Exception as e:
                if log_callback:
                    log_callback("WARNING", f"[Crawler] Failed to fetch {current_url}: {e}")
                continue

            content_type = resp.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                continue

            # Parse HTML
            soup = BeautifulSoup(resp.text, "html.parser")

            # Discover Forms
            for form_tag in soup.find_all("form"):
                action = form_tag.get("action") or current_url
                action_url = self.normalize_url(urljoin(current_url, action))
                method = form_tag.get("method", "GET").upper()

                inputs = []
                for inp in form_tag.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        inputs.append({
                            "name": name,
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", "")
                        })

                if inputs:
                    result.forms.append(CrawledForm(action_url, method, inputs))
                    if action_url not in result.parameters:
                        result.parameters[action_url] = set()
                    for inp in inputs:
                        result.parameters[action_url].add(inp["name"])

            # Discover Scripts & Stylesheets
            for script in soup.find_all("script", src=True):
                script_url = urljoin(current_url, script["src"])
                result.scripts.add(script_url)

            for link in soup.find_all("link", rel=lambda r: r and "stylesheet" in r, href=True):
                css_url = urljoin(current_url, link["href"])
                result.stylesheets.add(css_url)

            # Discover Links for deeper crawling
            if depth < self.max_depth:
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                        continue

                    full_url = self.normalize_url(urljoin(current_url, href))
                    if self.is_in_scope(full_url) and full_url not in visited:
                        queue.append((full_url, depth + 1))

        if log_callback:
            log_callback(
                "INFO",
                f"[Crawler] Crawl finished. Discovered {len(result.discovered_urls)} URLs, "
                f"{len(result.forms)} forms, {len(result.scripts)} scripts."
            )

        return result
