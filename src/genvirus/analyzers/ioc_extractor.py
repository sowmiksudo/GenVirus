"""IoC extraction and RFC-3986 deceptive URL (userinfo@host) detection."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from genvirus.core.models import DeceptiveURL, IoCReport

_URL_RE = re.compile(r"https?://[^\s\"'<>`\\]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|link|xyz|info|biz|invalid|test|local)\b")
_PATH_RE = re.compile(r"(?:/[A-Za-z0-9._-]+){2,}")

_SUSPICIOUS_CMD_PATTERNS: list[tuple[str, str]] = [
    ("eval_exec", r"\beval\s+[\"']"),
    ("mktemp_source", r"\bmktemp\b.*\bsource\b|\bsource\s+\$\{?[A-Za-z0-9_]+\}?"),
    ("rm_rf", r"\brm\s+-[rRfF]{1,3}\b"),
    ("curl_pipe_shell", r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)\b"),
    ("trap_signal", r"\btrap\s+['\"].*?(?:SIGINT|SIGTSTP|EXIT|2)"),
    ("xdg_open", r"\bxdg-open\s+"),
    ("base_decode_pipe", r"\bbase(?:64|32)\s+-d\b"),
]


def extract_iocs(text: str) -> IoCReport:
    """Extract URLs, masked @ URLs, IPv4 addresses, domains, paths, and shell heuristics."""
    urls = sorted(set(u.rstrip(".,;:)") for u in _URL_RE.findall(text)))

    deceptive_urls: list[DeceptiveURL] = []
    domains: set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname:
            domains.add(parsed.hostname)
        if parsed.username:
            deceptive_urls.append(
                DeceptiveURL(
                    full_url=url,
                    bait_userinfo=parsed.username,
                    true_host=parsed.hostname or "",
                    path=parsed.path or "/",
                )
            )

    for match in _DOMAIN_RE.findall(text):
        domains.add(match.lower())

    valid_ips: set[str] = set()
    for candidate in _IPV4_RE.findall(text):
        try:
            ipaddress.IPv4Address(candidate)
            valid_ips.add(candidate)
        except ValueError:
            continue

    paths = sorted(set(p for p in _PATH_RE.findall(text) if not p.startswith("//")))

    suspicious_cmds: list[str] = []
    for label, pattern in _SUSPICIOUS_CMD_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            suspicious_cmds.append(label)

    return IoCReport(
        urls=urls,
        deceptive_urls=deceptive_urls,
        ipv4_addresses=sorted(valid_ips),
        domains=sorted(domains),
        file_paths=paths[:30],
        suspicious_commands=sorted(set(suspicious_cmds)),
    )
