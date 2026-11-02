"""CMS / WAF / HTTP-server fingerprinting for web targets.

Fires an HTTP(S) request and inspects response headers + content markers to
identify the underlying CMS, WAF, and web server in one pass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx


# ---------------------------------------------------------------------------
# Fingerprint signatures
# ---------------------------------------------------------------------------

# Each rule: (name, header_key|None, content_regex|None, example)
# header_key: lowercase header to check (None = look in body)
# content_regex: optional regex to apply to body (first 8000 chars)

_WAF_RULES: list[dict[str, Any]] = [
    {"name": "Cloudflare", "header": "cf-ray", "example": "cf-ray: <id>.<edge>"},
    {"name": "Cloudflare", "header": "cf-cache-status", "example": ""},
    {"name": "Sucuri / Imperva WAF", "header": "x-imperva-uid", "example": ""},
    {"name": "Sucuri / Imperva WAF", "header": "server", "content_re": r"Imperva(?!\w)", "example": ""},
    {"name": "Akamai", "header": "server", "content_re": r"\bAkamai\w*", "example": ""},
    {"name": "Brotix WAF", "header": "x-brotix-id", "example": ""},
    {"name": "AWS WAF", "header": "server", "content_re": r"Amazon S3", "example": ""},
    {"name": "Vercel", "header": "x-vercel-id", "example": ""},
    {"name": "Vercel", "header": "x-viewport", "example": ""},
    {"name": "Fastly", "header": "x-served-by", "example": "x-served-by: cache-<edge>"},
    {"name": "Fastly", "header": "server", "content_re": r"\bFastly\b", "example": ""},
    {"name": "Varnish", "header": "via", "content_re": r"\bVarnish\b", "example": ""},
]

_CMS_RULES: list[dict[str, Any]] = [
    # Header-based
    {"name": "WordPress", "header": "x-powered-by", "content_re": r"WordPress", "example": ""},
    {"name": "WordPress", "header": "x-generator", "content_re": r"WordPress", "example": ""},
    {"name": "Laravel", "header": "x-powered-by", "content_re": r"Laravel", "example": ""},
    {"name": "Drupal", "header": "x-drupalsession", "example": ""},
    {"name": "Drupal", "header": "x-generator", "content_re": r"Drupal", "example": ""},
    {"name": "Joomla", "header": "x-generator", "content_re": r"Joomla", "example": ""},
    {"name": "Medusa", "header": "x-powered-by", "content_re": r"Medusa", "example": ""},
    # Body marker rules (path fragments, script tags, meta tags)
    {"name": "WordPress", "body_marker": "wp-content/", "example": "src=\"/wp-content/...\""},
    {"name": "WordPress", "body_marker": "wp-includes/", "example": ""},
    {"name": "WordPress", "body_marker": "xmlrpc.php", "example": ""},
    {"name": "Laravel", "body_marker": "laravel", "example": "data-component=\"laravel\""},
    {"name": "Laravel", "body_marker": "/build/assets/app.", "example": "Vite Laravel asset fingerprint"},
    {"name": "Laravel", "body_marker": "XSRF-TOKEN", "example": ""},
    {"name": "Vue", "body_marker": "data-v-", "example": "Vue SFC data-v-xxxx hash"},
    {"name": "Next.js", "body_marker": "__NEXT_DATA__", "example": ""},
    {"name": "Nuxt", "body_marker": "__NUXT__", "example": ""},
    {"name": "React", "body_marker": "data-reactroot", "example": ""},
    {"name": "Angular", "body_marker": "ng-version", "example": ""},
    {"name": "Shopify", "header": "x-shopify-storefront-token", "example": ""},
    {"name": "Shopify", "body_marker": "cdn.shopify.com", "example": ""},
    {"name": "Wix", "body_marker": "wixstatic.com", "example": ""},
    {"name": "Squarespace", "header": "server", "content_re": r"Squarespace", "example": ""},
    {"name": "Ghost", "body_marker": "ghost.org", "example": ""},
    {"name": "Eleventy", "body_marker": "built with 11ty", "example": ""},
    {"name": "Bootstrap", "body_marker": "bootstrap.min.css", "example": ""},
    {"name": "Tailwind CSS", "body_marker": "tailwind", "example": ""},
    {"name": "jQuery", "body_marker": "jquery.min.js", "example": ""},
    {"name": "Gatsby", "body_marker": "__gatsby", "example": ""},
    {"name": "Astro", "body_marker": "data-astro-", "example": ""},
    {"name": "SvelteKit", "body_marker": "sveltekit", "example": ""},
    {"name": "Django", "body_marker": "csrfmiddlewaretoken", "example": ""},
    {"name": "Ruby on Rails", "body_marker": "csrf-token", "example": ""},
]

_SERVER_RULES: list[dict[str, Any]] = [
    {"name": "Apache", "header": "server", "content_re": r"Apache\b"},
    {"name": "Nginx", "header": "server", "content_re": r"nginx\b"},
    {"name": "IIS", "header": "server", "content_re": r"Microsoft-IIS"},
    {"name": "Gunicorn", "header": "server", "content_re": r"gunicorn"},
    {"name": "uWSGI", "header": "server", "content_re": r"uwsgi"},
    {"name": "Caddy", "header": "server", "content_re": r"\bCaddy\b"},
    {"name": "LiteSpeed", "header": "server", "content_re": r"LiteSpeed"},
    {"name": "Envoy", "header": "server", "content_re": r"envoy"},
    {"name": "Tomcat", "header": "server", "content_re": r"Apache Tomcat"},
    {"name": "Jetty", "header": "server", "content_re": r"\bJetty\b"},
    {"name": "Play", "header": "server", "content_re": r"\bPlay\b"},
    {"name": "Heroku", "header": "x-powered-by", "content_re": r"Heroku"},
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TechDetectionReport:
    """Aggregated technology fingerprint for one domain."""

    domain: str
    cms_list: list[str] = field(default_factory=list)
    waf_list: list[str] = field(default_factory=list)
    server_list: list[str] = field(default_factory=list)
    http_status: int | None = None
    url_used: str = ""
    error: str = ""

    @property
    def has_cms(self) -> bool:
        return len(self.cms_list) > 0

    @property
    def has_waf(self) -> bool:
        return len(self.waf_list) > 0


# ---------------------------------------------------------------------------
# Fingerprint matching
# ---------------------------------------------------------------------------

def _match_rules(rules: list[dict[str, Any]], headers: httpx.Headers, body: str) -> list[str]:
    """Return the set of unique tech names that match any rule in *rules*."""
    found: set[str] = set()
    for rule in rules:
        name = rule["name"]
        if found and name in found:
            continue
        matched = False
        header_key = rule.get("header")
        if header_key:
            value = headers.get(header_key, "")
            content_re = rule.get("content_re")
            if content_re:
                if re.search(content_re, value, re.IGNORECASE):
                    matched = True
            elif value:
                matched = True
        if not matched and rule.get("body_marker"):
            marker = rule["body_marker"].lower()
            if marker in body.lower():
                matched = True
        if matched:
            found.add(name)
    return sorted(found)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def detect_tech(domain: str) -> TechDetectionReport:
    """Fetch the root page and fingerprint CMS, WAF, and HTTP server."""
    report = TechDetectionReport(domain=domain)
    url = f"https://{domain}"

    try:
        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (KMC-RESOLVX/1.0)"},
        ) as client:
            response = await client.get(url)
            report.http_status = response.status_code
            report.url_used = str(response.url)
            headers = response.headers
            body = response.text[:8000]  # only need head fragment

            report.waf_list = _match_rules(_WAF_RULES, headers, body)
            report.cms_list = _match_rules(_CMS_RULES, headers, body)
            report.server_list = _match_rules(_SERVER_RULES, headers, "")
    except httpx.ConnectError as exc:
        report.error = f"ConnectError: {exc}"
    except httpx.TimeoutException as exc:
        report.error = f"Timeout: {exc}"
    except Exception as exc:
        report.error = f"{exc.__class__.__name__}: {exc}"

    return report
