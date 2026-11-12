"""Scope: the single authority on which hosts Reconic may touch or report.

Patterns
    app.example.com     exactly that host
    *.example.com       any subdomain of example.com, at any depth (not the apex)
    api-*.example.com   glob inside a label
    10.0.0.0/24         every address in the network
Exclusions always win over inclusions. A port on an exact host
('app.example.com:8443') does not narrow the scope, which is per host; it says
where that host is probed.

A scope also says where a scan starts: exact hosts and network addresses are
tested as they are, and a wildcard pattern is enumerated from its fixed
suffix ('api-*.example.com' -> 'example.com').
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

_HOST_RE = re.compile(r'^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$')
_PATTERN_RE = re.compile(r'^[a-z0-9_.*-]+$')
_GLOB_CHARS = '[a-z0-9_.-]*'
MAX_NETWORK_HOSTS = 65536


def is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def host_of(target: str) -> Optional[str]:
    """Hostname of a bare host, host:port or URL; None when it isn't a valid host."""
    text = target.strip()
    if not text:
        return None
    if '://' not in text:
        text = '//' + text
    try:
        parts = urlsplit(text)
        host = parts.hostname
        parts.port  # raises on a non-numeric port, e.g. 'javascript:alert(1)'
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower().rstrip('.')
    if _HOST_RE.match(host):
        return host
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


class _Pattern:
    def __init__(self, raw: str):
        text = raw.strip().lower()
        self.network = None
        self.regex = None
        self.ports: List[int] = []
        if '://' not in text and '/' in text:
            try:
                self.network = ipaddress.ip_network(text, strict=False)
                self.text = str(self.network)
                return
            except ValueError:
                pass
        if '://' in text:
            text = text.split('://', 1)[1]
        text = re.split(r'[/?#]', text, maxsplit=1)[0]
        port = re.search(r':(\d+)$', text)
        if port and 0 < int(port.group(1)) < 65536 and '*' not in text:
            self.ports.append(int(port.group(1)))
        text = re.sub(r':\d+$', '', text).rstrip('.')
        if not text or not _PATTERN_RE.match(text):
            raise ValueError(f"invalid scope pattern: {raw!r}")
        self.text = text
        self.host_regex = ''.join(_GLOB_CHARS if ch == '*' else re.escape(ch) for ch in text)
        self.regex = re.compile(self.host_regex)

    @property
    def is_exact(self) -> bool:
        return self.network is None and '*' not in self.text

    @property
    def root(self) -> Optional[str]:
        """The domain to enumerate for a wildcard pattern: the labels after its last wildcard."""
        if self.network is not None or '*' not in self.text:
            return None
        suffix = self.text.rsplit('*', 1)[1].partition('.')[2]
        return suffix if '.' in suffix else None

    def matches(self, host: str) -> bool:
        if self.network is not None:
            try:
                return ipaddress.ip_address(host) in self.network
            except ValueError:
                return False
        return self.regex.fullmatch(host) is not None


def _patterns(raw: Iterable[str]) -> List[_Pattern]:
    seen: dict = {}
    out = []
    for item in raw:
        pattern = _Pattern(item)
        if pattern.text not in seen:
            seen[pattern.text] = pattern
            out.append(pattern)
        else:
            seen[pattern.text].ports += [port for port in pattern.ports if port not in seen[pattern.text].ports]
    return out


class Scope:
    def __init__(self, include: Iterable[str], exclude: Iterable[str] = ()):
        self._include = _patterns(include)
        self._exclude = _patterns(exclude)
        if not self._include:
            raise ValueError("scope is empty: give at least one domain, host or pattern")
        addresses = sum(p.network.num_addresses for p in self._include if p.network is not None)
        if addresses > MAX_NETWORK_HOSTS:
            raise ValueError(f"the networks in scope hold {addresses} addresses; the limit is "
                             f"{MAX_NETWORK_HOSTS}, so split them into smaller scans")

    @staticmethod
    def parse_file(path: Path) -> Tuple[List[str], List[str]]:
        """Read a scope file: one pattern per line, '!' prefix excludes, '#' comments."""
        include, exclude = [], []
        for line in Path(path).read_text(encoding='utf-8').splitlines():
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            if line.startswith('!'):
                exclude.append(line[1:].strip())
            else:
                include.append(line)
        return include, exclude

    @property
    def include(self) -> List[str]:
        return [p.text for p in self._include]

    @property
    def exclude(self) -> List[str]:
        return [p.text for p in self._exclude]

    def allows(self, target: str) -> bool:
        """True when the host of `target` (host or URL) is included and not excluded."""
        host = host_of(target)
        if host is None:
            return False
        if any(p.matches(host) for p in self._exclude):
            return False
        return any(p.matches(host) for p in self._include)

    def split(self, targets: Iterable[str]) -> Tuple[List[str], int]:
        """Return the in-scope targets (deduplicated, order kept) and how many were dropped."""
        kept, seen, dropped = [], set(), 0
        for target in targets:
            target = target.strip()
            if not target or target in seen:
                continue
            seen.add(target)
            if self.allows(target):
                kept.append(target)
            else:
                dropped += 1
        return kept, dropped

    def enumeration_roots(self) -> List[str]:
        """Domains to enumerate for the wildcard patterns ('*.example.com' -> 'example.com').

        What enumeration returns still has to pass the scope, so 'api-*.example.com'
        enumerates example.com and keeps only the hosts that match the pattern.
        """
        roots = []
        for pattern in self._include:
            if pattern.root and pattern.root not in roots:
                roots.append(pattern.root)
        return roots

    def exact_hosts(self) -> List[str]:
        """Hosts named outright in the scope, minus exclusions."""
        return [p.text for p in self._include if p.is_exact and self.allows(p.text)]

    def seeds(self) -> List[str]:
        """Hosts to test as they are: the exact hosts, then every address of the networks."""
        hosts = self.exact_hosts()
        seen = set(hosts)
        for pattern in self._include:
            if pattern.network is None:
                continue
            for address in pattern.network.hosts():
                host = str(address)
                if host not in seen and self.allows(host):
                    seen.add(host)
                    hosts.append(host)
        return hosts

    def unseeded(self) -> List[str]:
        """Patterns that match hosts but name neither a host nor a domain to start from ('example.*')."""
        return [p.text for p in self._include if p.network is None and not p.is_exact and not p.root]

    def url_regexes(self) -> Optional[Tuple[List[str], List[str]]]:
        """(in-scope, out-of-scope) URL regexes for crawlers; None if the scope has networks."""
        if any(p.network is not None for p in self._include + self._exclude):
            return None

        def as_url(pattern: _Pattern) -> str:
            return f"(?i)^https?://{pattern.host_regex}(:[0-9]+)?([/?#]|$)"

        return [as_url(p) for p in self._include], [as_url(p) for p in self._exclude]

    def probe_targets(self, host: str) -> List[str]:
        """What to probe for a host: host:port for each port the scope names for it, else the host."""
        ports = next((p.ports for p in self._include if p.is_exact and p.text == host), [])
        return [f"{host}:{port}" for port in ports] or [host]

    def ports(self) -> dict:
        return {p.text: list(p.ports) for p in self._include if p.ports}

    def to_dict(self) -> dict:
        scope = {'include': self.include, 'exclude': self.exclude}
        if self.ports():
            scope['ports'] = self.ports()
        return scope
