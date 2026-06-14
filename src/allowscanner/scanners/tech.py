"""Technology detection scanner."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, TypedDict

from ..core.models import Technology

if TYPE_CHECKING:
    from .http import HttpClient


class TechSignature(TypedDict, total=False):
    patterns: list[str]
    headers: list[str]
    cookies: list[str]
    category: str


TECH_SIGNATURES: dict[str, TechSignature] = {
    "WordPress": {
        "patterns": ["wp-content", "wp-includes", "wordpress", "wp-emoji"],
        "headers": ["x-pingback"],
        "cookies": ["wordpress_logged_in", "wp-settings"],
        "category": "CMS",
    },
    "Joomla": {
        "patterns": ["joomla", "/media/jui/", "Joomla! is Free"],
        "category": "CMS",
    },
    "Drupal": {
        "patterns": ["Drupal.settings", "drupal.js", "sites/all/", "drupal-"],
        "headers": ["x-drupal-cache", "x-generator: drupal"],
        "category": "CMS",
    },
    "Laravel": {
        "patterns": ["laravel", "csrf-token", "XSRF-TOKEN", "laravel_session"],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "category": "Framework",
    },
    "React": {
        "patterns": ["react", "__NEXT_DATA__", "_reactRootContainer", "data-reactroot"],
        "category": "Frontend",
    },
    "Next.js": {
        "patterns": ["__NEXT_DATA__", "/_next/", "next.js"],
        "headers": ["x-powered-by: next"],
        "category": "Framework",
    },
    "Vue.js": {
        "patterns": ["vue.js", "__vue__", "data-v-", "v-bind", "nuxt"],
        "category": "Frontend",
    },
    "Angular": {
        "patterns": ["ng-app", "ng-controller", "angular.js", "angular.min.js", "[ng-"],
        "category": "Frontend",
    },
    "jQuery": {
        "patterns": ["jquery", "jQuery.fn.jquery"],
        "category": "Library",
    },
    "Bootstrap": {
        "patterns": ["bootstrap.min.css", "bootstrap.min.js", "navbar-toggler"],
        "category": "CSS Framework",
    },
    "Tailwind CSS": {
        "patterns": ["tailwind", "tw-"],
        "category": "CSS Framework",
    },
    "Express": {
        "headers": ["x-powered-by: express"],
        "category": "Backend",
    },
    "Django": {
        "patterns": ["csrfmiddlewaretoken", "django", "csrftoken"],
        "cookies": ["csrftoken", "sessionid"],
        "category": "Framework",
    },
    "Flask": {
        "patterns": ["flask", "werkzeug"],
        "cookies": ["session"],
        "category": "Framework",
    },
    "Ruby on Rails": {
        "patterns": ["rails", "csrf-token", "authenticity_token"],
        "cookies": ["_rails_session"],
        "category": "Framework",
    },
    "Spring Boot": {
        "patterns": ["spring", "X-Application-Context"],
        "headers": ["x-application-context"],
        "category": "Framework",
    },
    "ASP.NET": {
        "patterns": ["__VIEWSTATE", "asp.net", "__EVENTVALIDATION"],
        "headers": ["x-aspnet-version", "x-powered-by: asp.net"],
        "category": "Framework",
    },
    "PHP": {
        "patterns": ["php", "PHPSESSID"],
        "cookies": ["PHPSESSID"],
        "headers": ["x-powered-by: php"],
        "category": "Language",
    },
    "Node.js": {
        "headers": ["x-powered-by: express"],
        "category": "Runtime",
    },
    "Nginx": {
        "headers": ["server: nginx", "server:nginx"],
        "category": "Web Server",
    },
    "Apache": {
        "headers": ["server: apache", "server:apache"],
        "category": "Web Server",
    },
    "Cloudflare": {
        "headers": ["server: cloudflare", "cf-ray"],
        "patterns": ["cloudflare", "cf-ray"],
        "category": "CDN/WAF",
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "via: fastly"],
        "category": "CDN",
    },
    "Varnish": {
        "headers": ["x-varnish", "via: varnish"],
        "category": "Cache",
    },
    "Docker": {
        "patterns": ["docker", "container"],
        "category": "Infrastructure",
    },
    "Kubernetes": {
        "patterns": ["kubernetes", "kubectl"],
        "category": "Infrastructure",
    },
    "GraphQL": {
        "patterns": ["graphql", "__schema", "IntrospectionQuery"],
        "category": "API",
    },
    "gRPC": {
        "headers": ["content-type: application/grpc"],
        "category": "API",
    },
}


class TechScanner:
    """Detect web technologies, frameworks, and servers."""

    async def scan(self, url: str, session: HttpClient) -> list[Technology]:
        technologies: list[Technology] = []
        seen: set[str] = set()

        resp, content = await session.get(url)
        if not resp:
            return technologies

        content_lower = content.lower()
        response_headers = resp.headers

        # Create a lowercase version of headers for case-insensitive matching
        headers_lower = {}
        for key, value in response_headers.items():
            headers_lower[key.lower()] = value.lower()

        for tech_name, sig in TECH_SIGNATURES.items():
            if tech_name in seen:
                continue

            found = False

            # Check content patterns
            for pattern in sig.get("patterns", []):
                if pattern.lower() in content_lower:
                    found = True
                    break

            # Check response headers (case-insensitive)
            if not found:
                for header_sig in sig.get("headers", []):
                    if ":" in header_sig:
                        h_name, h_val = header_sig.split(":", 1)
                        h_name_lower = h_name.strip().lower()
                        h_val_lower = h_val.strip().lower()
                        # Check if header exists and contains the expected value
                        if h_name_lower in headers_lower and h_val_lower in headers_lower[h_name_lower]:
                            found = True
                            break
                    else:
                        # Just check if header name exists
                        if header_sig.lower() in headers_lower:
                            found = True
                            break

            # Check cookies
            if not found:
                for cookie_name in sig.get("cookies", []):
                    for cookie in resp.cookies.values():
                        if cookie_name.lower() in cookie.key.lower():
                            found = True
                            break

            if found:
                seen.add(tech_name)
                technologies.append(
                    Technology(
                        name=tech_name,
                        category=sig.get("category", ""),
                    )
                )

        # Try to detect versions from meta generator tag
        gen_match = re.search(r'<meta[^>]*name="generator"[^>]*content="([^"]+)"', content, re.IGNORECASE)
        if gen_match:
            gen = gen_match.group(1)
            for tech in technologies:
                if tech.name.lower() in gen.lower():
                    # Extract version
                    ver_match = re.search(r"(\d+\.[\d.]+)", gen)
                    if ver_match:
                        tech.version = ver_match.group(1)

        return technologies
