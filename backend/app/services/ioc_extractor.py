"""
ClarityTI IOC Extraction Engine
Extracts 25+ indicator types from raw text using regex patterns + defanging.
"""
import re
from typing import Dict, List
from dataclasses import dataclass, field


@dataclass
class ExtractedIOCs:
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    cidr: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    sha256: List[str] = field(default_factory=list)
    sha1: List[str] = field(default_factory=list)
    md5: List[str] = field(default_factory=list)
    filenames: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    mutex: List[str] = field(default_factory=list)
    scheduled_tasks: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)
    asn: List[str] = field(default_factory=list)
    named_pipes: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    powershell: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    bitcoin_addresses: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: list(set(v)) for k, v in self.__dict__.items() if v}

    @property
    def total_count(self) -> int:
        return sum(len(v) for v in self.__dict__.values())


# ── Refang: normalize defanged indicators ─────────────────────────────────────

def refang(text: str) -> str:
    """Convert defanged indicators back to fanged form for extraction."""
    text = re.sub(r'\[?\.\]?', '.', text)          # [.] → .
    text = re.sub(r'hxxp://', 'http://', text, flags=re.I)
    text = re.sub(r'hxxps://', 'https://', text, flags=re.I)
    text = re.sub(r'\[@\]', '@', text)              # [@] → @
    text = re.sub(r'\[at\]', '@', text, flags=re.I)
    text = re.sub(r'\s+dot\s+', '.', text, flags=re.I)
    text = re.sub(r'\[dot\]', '.', text, flags=re.I)
    return text


# ── Regex Patterns ────────────────────────────────────────────────────────────

_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'
)
_CIDR = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}\b'
)
_URL = re.compile(
    r'https?://[^\s<>"\'{}|\\^`\[\]]{3,}'
)
_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|co|ru|cn|de|uk|fr|jp|br|au|int|biz|info|name|pro|tech|online|site|xyz|top|club|store|shop|live|news|media|app|dev|security|ninja)\b',
    re.I
)
_EMAIL = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)
_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
_SHA1   = re.compile(r'\b[0-9a-fA-F]{40}\b')
_MD5    = re.compile(r'\b[0-9a-fA-F]{32}\b')
_CVE    = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
_REGISTRY = re.compile(
    r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)(?:\\[^\\\s\n"\'<>]{1,200})+',
    re.I
)
_MUTEX = re.compile(r'(?:Global|Local)\\[A-Za-z0-9_\-\.]{3,64}')
_NAMED_PIPE = re.compile(r'\\\\.\\pipe\\[A-Za-z0-9_\-\.]{1,64}')
_WIN_PATH = re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\s]{1,200}\\)+[^\\/:*?"<>|\r\n\s]{0,200}')
_UNIX_PATH = re.compile(r'(?<!\w)/(?:etc|tmp|var|usr|home|opt|bin|sbin|proc|sys|root)/[^\s<>"\']{1,200}')
_ASN = re.compile(r'\bAS\d{1,7}\b')
_BITCOIN = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
_SCHED_TASK = re.compile(r'(?:schtasks|at)\s+[/\\][a-zA-Z].*', re.I)
_POWERSHELL = re.compile(
    r'(?:powershell|pwsh)[.\s][^\n]{10,200}',
    re.I
)
_USER_AGENT = re.compile(r'Mozilla/[0-9]\.[0-9][^\n"\']{5,150}')
_PORT = re.compile(r'(?:port|PORT)\s*:?\s*(\d{2,5})\b')


# ── Private IPs (excluded from extraction) ───────────────────────────────────

_PRIVATE_IP_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
    re.compile(r'^0\.0\.0\.0'),
    re.compile(r'^255\.255\.255\.255'),
]

_COMMON_DOMAINS_ALLOWLIST = {
    "github.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "cloudflare.com", "example.com", "localhost",
    "windows.com", "office.com", "live.com", "outlook.com",
    "twitter.com", "linkedin.com", "facebook.com",
}


def _is_private_ip(ip: str) -> bool:
    return any(r.match(ip) for r in _PRIVATE_IP_RANGES)


def _is_allowlisted_domain(domain: str) -> bool:
    return domain.lower() in _COMMON_DOMAINS_ALLOWLIST


# ── Main Extractor ────────────────────────────────────────────────────────────

class IOCExtractor:
    """
    Enterprise IOC extraction engine.
    Handles defanged IOCs, filters private IPs, deduplicates.
    """

    def extract(self, text: str) -> ExtractedIOCs:
        """Extract all IOC types from text."""
        result = ExtractedIOCs()

        # Refang the text first (handle defanged indicators)
        refanged = refang(text)

        # CIDRs (before IPs to avoid partial match)
        for m in _CIDR.finditer(refanged):
            result.cidr.append(m.group())

        # IPv4 (excluding private ranges)
        for m in _IPV4.finditer(refanged):
            ip = m.group()
            if not _is_private_ip(ip) and ip not in [c.split('/')[0] for c in result.cidr]:
                result.ipv4.append(ip)

        # IPv6
        for m in _IPV6.finditer(refanged):
            result.ipv6.append(m.group())

        # URLs (before domains to avoid duplication)
        urls_found = set()
        for m in _URL.finditer(refanged):
            url = m.group().rstrip('.,;)')
            urls_found.add(url)
            result.urls.append(url)

        # Domains (filter out from URLs already captured and allowlisted)
        for m in _DOMAIN.finditer(refanged):
            domain = m.group().lower()
            if (not _is_allowlisted_domain(domain)
                    and not any(domain in u for u in urls_found)
                    and len(domain) > 4):
                result.domains.append(domain)

        # Emails
        for m in _EMAIL.finditer(refanged):
            email = m.group()
            if not any(email in d for d in result.domains):
                result.emails.append(email)

        # Hashes
        for m in _SHA256.finditer(refanged):
            result.sha256.append(m.group().lower())

        for m in _SHA1.finditer(refanged):
            h = m.group().lower()
            if h not in result.sha256:
                result.sha1.append(h)

        for m in _MD5.finditer(refanged):
            h = m.group().lower()
            if h not in result.sha256 and h not in result.sha1:
                result.md5.append(h)

        # CVEs
        for m in _CVE.finditer(text):
            result.cves.append(m.group().upper())

        # Registry keys
        for m in _REGISTRY.finditer(text):
            result.registry_keys.append(m.group())

        # Mutex
        for m in _MUTEX.finditer(text):
            result.mutex.append(m.group())

        # Named pipes
        for m in _NAMED_PIPE.finditer(text):
            result.named_pipes.append(m.group())

        # File paths
        for m in _WIN_PATH.finditer(text):
            result.file_paths.append(m.group())
        for m in _UNIX_PATH.finditer(text):
            result.file_paths.append(m.group())

        # ASNs
        for m in _ASN.finditer(text):
            result.asn.append(m.group())

        # Bitcoin addresses
        for m in _BITCOIN.finditer(text):
            result.bitcoin_addresses.append(m.group())

        # PowerShell snippets
        for m in _POWERSHELL.finditer(text):
            result.powershell.append(m.group().strip()[:500])

        # Ports
        for m in _PORT.finditer(text):
            port = m.group(1)
            if 1 <= int(port) <= 65535:
                result.ports.append(port)

        # User agents
        for m in _USER_AGENT.finditer(text):
            result.user_agents.append(m.group()[:200])

        # Deduplicate all lists
        for field_name in result.__dataclass_fields__:
            setattr(result, field_name, list(dict.fromkeys(getattr(result, field_name))))

        return result


# ── Defanging for output ──────────────────────────────────────────────────────

def defang_iocs(iocs: ExtractedIOCs) -> ExtractedIOCs:
    """Convert extracted IOCs to defanged form for safe sharing."""
    def defang_ip(ip: str) -> str:
        return ip.replace('.', '[.]')

    def defang_domain(d: str) -> str:
        return d.replace('.', '[.]')

    def defang_url(u: str) -> str:
        return u.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')

    iocs.ipv4 = [defang_ip(ip) for ip in iocs.ipv4]
    iocs.domains = [defang_domain(d) for d in iocs.domains]
    iocs.urls = [defang_url(u) for u in iocs.urls]
    return iocs
