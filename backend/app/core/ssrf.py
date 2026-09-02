"""
Enterprise SSRF (Server-Side Request Forgery) Defense & Safe HTTP Transport Layer.

Provides multi-layer security against:
- Loopback addresses (127.0.0.0/8, ::1)
- Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
- Link-local & APIPA ranges (169.254.0.0/16, fe80::/10)
- Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
- Carrier-grade NAT (100.64.0.0/10) & reserved address space
- DNS rebinding & malicious redirect destinations
- Non-HTTP/HTTPS protocols (file://, gopher://, ftp://, dict://)
"""
import socket
import ipaddress
import urllib.parse
from typing import Optional, Tuple, List
import httpx
import structlog

log = structlog.get_logger()

# Disallowed internal/metadata domain suffixes and exact hostnames
_DISALLOWED_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "::1",
    "metadata.google.internal",
    "instance-data",
}

_DISALLOWED_SUFFIXES = (
    ".local",
    ".internal",
    ".localhost",
    ".lan",
    ".home",
    ".corp",
    ".test",
    ".invalid",
)

# Explicitly blocked CIDRs (IPv4 and IPv6)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("2001::/23"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("2002::/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address falls in any private/loopback/cloud-metadata CIDRs."""
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    
    # Check against mapped IPv4 inside IPv6
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        if is_ip_blocked(ip.ipv4_mapped):
            return True

    for net in _BLOCKED_NETWORKS:
        if ip in net:
            return True

    return False


def validate_hostname_and_dns(hostname: str) -> Tuple[bool, Optional[str]]:
    """
    Validates hostname and resolves DNS to verify no IP is in blocked ranges.
    Returns (is_valid, error_reason).
    """
    if not hostname or not isinstance(hostname, str):
        return False, "Empty or invalid hostname"

    host_clean = hostname.strip().lower()

    if host_clean in _DISALLOWED_HOSTNAMES:
        return False, f"Host '{host_clean}' is in disallowed hosts list"

    for suffix in _DISALLOWED_SUFFIXES:
        if host_clean.endswith(suffix):
            return False, f"Host '{host_clean}' has prohibited domain suffix '{suffix}'"

    # Try parsing direct IP
    try:
        ip = ipaddress.ip_address(host_clean)
        if is_ip_blocked(ip):
            return False, f"Direct IP '{ip}' is in a private/restricted network range"
        return True, None
    except ValueError:
        pass  # It is a domain name, resolve via DNS

    # Perform DNS resolution
    try:
        addr_info = socket.getaddrinfo(host_clean, None)
        resolved_ips: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                resolved_ips.append(ip_obj)
            except ValueError:
                continue

        if not resolved_ips:
            return False, f"No IP addresses resolved for domain '{host_clean}'"

        for resolved_ip in resolved_ips:
            if is_ip_blocked(resolved_ip):
                return False, f"Domain '{host_clean}' resolved to restricted IP '{resolved_ip}'"

        return True, None
    except socket.gaierror as e:
        return False, f"DNS resolution failed for '{host_clean}': {e}"
    except Exception as e:
        return False, f"Error validating hostname '{host_clean}': {e}"


def is_safe_public_url(url: str) -> bool:
    """
    Public utility to check if a URL is safe against SSRF attacks.
    """
    if not url or not isinstance(url, str):
        return False

    url_str = url.strip()
    try:
        parsed = urllib.parse.urlparse(url_str)
    except Exception:
        return False

    if parsed.scheme.lower() not in ("http", "https"):
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    is_valid, _ = validate_hostname_and_dns(hostname)
    return is_valid


async def safe_fetch_url(
    url: str,
    headers: Optional[dict] = None,
    timeout: float = 15.0,
    max_bytes: int = 5_000_000,
    max_redirects: int = 3,
) -> Tuple[bool, Optional[str], Optional[bytes], Optional[str]]:
    """
    Safely fetches a URL with step-by-step redirect validation to prevent SSRF via redirects.
    Returns: (success, status_code_or_reason, content_bytes, content_type)
    """
    current_url = url
    current_redirects = 0

    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ClarityTI-CTI-Collector/2.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/xml;q=0.8,*/*;q=0.8",
    }
    if headers:
        default_headers.update(headers)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=5.0),
        headers=default_headers,
        follow_redirects=False,
        verify=True,
    ) as client:
        while current_redirects <= max_redirects:
            if not is_safe_public_url(current_url):
                return False, f"Blocked unsafe/internal URL target: {current_url}", None, None

            try:
                resp = await client.get(current_url)
            except Exception as e:
                return False, f"HTTP fetch failed: {e}", None, None

            # Check if redirect
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                if not location:
                    return False, "Redirect status without Location header", None, None

                # Resolve relative redirect
                next_url = urllib.parse.urljoin(current_url, location)
                current_url = next_url
                current_redirects += 1
                continue

            if resp.status_code >= 400:
                return False, f"HTTP Error {resp.status_code}", None, None

            content = resp.content
            if len(content) > max_bytes:
                return False, f"Response size ({len(content)} bytes) exceeds limit ({max_bytes} bytes)", None, None

            content_type = resp.headers.get("content-type", "")
            return True, str(resp.status_code), content, content_type

        return False, "Exceeded maximum allowed redirects", None, None
