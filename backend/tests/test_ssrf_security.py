"""
Automated Test Suite for SSRF (Server-Side Request Forgery) Defense.

Tests:
1. Direct loopback IPs (127.0.0.1, 127.0.0.2, ::1)
2. Private IPv4 address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
3. Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
4. Non-HTTP schemes (file://, gopher://, ftp://, dict://)
5. Prohibited domain names and suffixes (.local, .internal, .localhost, .lan)
6. Legitimate public HTTP/HTTPS URLs pass validation
"""
import pytest
import ipaddress
from app.core.ssrf import (
    is_safe_public_url,
    is_ip_blocked,
    validate_hostname_and_dns
)


def test_loopback_ips_blocked():
    """All IPv4 and IPv6 loopback variants must be rejected."""
    blocked_urls = [
        "http://127.0.0.1/feed.xml",
        "http://127.0.0.2:8080/admin",
        "http://127.255.255.254/rss",
        "http://localhost:8000/feed",
        "https://localhost/api",
        "http://[::1]/rss.atom",
    ]
    for url in blocked_urls:
        assert is_safe_public_url(url) is False, f"Loopback URL allowed: {url}"


def test_private_ip_ranges_blocked():
    """RFC 1918 private IPv4 networks must be rejected."""
    private_urls = [
        "http://10.0.0.1/rss",
        "http://10.254.254.254/feed.xml",
        "http://172.16.0.1/admin/feed",
        "http://172.31.255.255/rss",
        "http://192.168.1.1/feed",
        "http://192.168.100.50:8080/feed",
    ]
    for url in private_urls:
        assert is_safe_public_url(url) is False, f"Private IP URL allowed: {url}"


def test_cloud_metadata_endpoints_blocked():
    """AWS/GCP/Azure link-local cloud metadata endpoints must be strictly blocked."""
    metadata_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.253/metadata",
        "http://instance-data/latest/meta-data/",
    ]
    for url in metadata_urls:
        assert is_safe_public_url(url) is False, f"Cloud metadata URL allowed: {url}"


def test_non_http_schemes_blocked():
    """Protocols other than http:// and https:// must be rejected."""
    non_http_urls = [
        "file:///etc/passwd",
        "file:///C:/Windows/win.ini",
        "gopher://127.0.0.1:70/",
        "ftp://public.mirror/feed.xml",
        "dict://127.0.0.1:11211/stat",
        "ldap://127.0.0.1:389/dc=example",
        "data:text/html,<script>alert(1)</script>",
    ]
    for url in non_http_urls:
        assert is_safe_public_url(url) is False, f"Non-HTTP scheme allowed: {url}"


def test_disallowed_domain_suffixes_blocked():
    """Internal/local domain suffixes must be rejected."""
    internal_domains = [
        "http://kubernetes.default.svc.cluster.local/rss",
        "http://database.corp.internal/feed",
        "http://router.home.lan/feed.xml",
        "http://myservice.test/api",
        "http://test.invalid/feed",
    ]
    for url in internal_domains:
        assert is_safe_public_url(url) is False, f"Internal domain allowed: {url}"


def test_legitimate_public_urls_allowed():
    """Verified public threat intelligence feeds must be permitted."""
    public_urls = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://threatpost.com/feed/",
        "https://krebsonsecurity.com/feed/",
    ]
    for url in public_urls:
        assert is_safe_public_url(url) is True, f"Legitimate public URL blocked: {url}"
