"""Scope firewall: a local proxy that only connects to in-scope hosts.

The tools that contact targets are pointed at it, so a redirect, a template or
a crawled link cannot make them reach a host outside the scope. Every
connection attempt, allowed or blocked, is appended to the run's scope receipt.

Plain HTTP requests are visible to it in full, so for those it also refuses
forbidden paths and checks that the required headers are present. HTTPS is
tunnelled and stays opaque: there only the host is checked.

It speaks both HTTP (CONNECT and plain requests) and SOCKS5 on one port, and
can chain to an upstream HTTP or SOCKS5 proxy.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote, urlsplit

from .scope import Scope

RECEIPT_NAME = 'scope_receipt.jsonl'
_TIMEOUT = 30
_UPSTREAM_TIMEOUT = 90  # a connect through Tor can take longer than 30s while it builds a circuit
_HEAD_LIMIT = 1 << 20
_HOP_HEADERS = ('proxy-connection', 'proxy-authorization', 'connection', 'keep-alive')
# Requests a tool makes on its own account whenever it is given a proxy. They are
# refused like anything else out of scope, but are not counted as an attempt to leave it.
_TOOL_PROBES = {'burpsuite': "katana looks for a Burp certificate whenever it is given a proxy"}
_Stream = Tuple[asyncio.StreamReader, asyncio.StreamWriter]


class FirewallError(Exception):
    """The upstream proxy refused or could not make a connection."""


class Upstream:
    """The user's own proxy, which allowed connections are chained through."""

    def __init__(self, url: str):
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ('http', 'https', 'socks5', 'socks5h') or not parts.hostname:
            raise ValueError(f"the scope firewall can only chain to an http(s) or socks5 proxy, not {url!r}; "
                             "use another proxy or pass --no-firewall")
        self.socks = scheme.startswith('socks5')
        self.tls = scheme == 'https'
        self.host = parts.hostname
        self.port = parts.port or (1080 if self.socks else 443 if self.tls else 8080)
        self.username = unquote(parts.username or '')
        self.password = unquote(parts.password or '')

    @property
    def basic_auth(self) -> Optional[str]:
        if not self.username:
            return None
        token = base64.b64encode(f"{self.username}:{self.password}".encode('utf-8')).decode('ascii')
        return f"Proxy-Authorization: Basic {token}"


def _socks_address(host: str) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode('idna')
        return b'\x03' + bytes([len(name)]) + name
    return (b'\x01' if address.version == 4 else b'\x04') + address.packed


async def _read_socks_address(reader: asyncio.StreamReader, kind: int) -> str:
    if kind == 1:
        return str(ipaddress.ip_address(await reader.readexactly(4)))
    if kind == 4:
        return str(ipaddress.ip_address(await reader.readexactly(16)))
    if kind == 3:
        length = (await reader.readexactly(1))[0]
        return (await reader.readexactly(length)).decode('ascii', errors='replace').lower().rstrip('.')
    raise FirewallError(f"unknown SOCKS5 address type {kind}")


async def _socks5_connect(stream: _Stream, upstream: Upstream, host: str, port: int) -> None:
    reader, writer = stream
    writer.write(b'\x05\x02\x00\x02' if upstream.username else b'\x05\x01\x00')
    method = (await reader.readexactly(2))[1]
    if method == 2:
        user, password = upstream.username.encode('utf-8'), upstream.password.encode('utf-8')
        writer.write(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
        if (await reader.readexactly(2))[1] != 0:
            raise FirewallError("upstream proxy rejected the credentials")
    elif method != 0:
        raise FirewallError("upstream proxy offered no usable authentication method")
    writer.write(b'\x05\x01\x00' + _socks_address(host) + port.to_bytes(2, 'big'))
    reply = await reader.readexactly(4)
    if reply[1] != 0:
        raise FirewallError(f"upstream proxy could not connect (SOCKS5 reply {reply[1]})")
    await _read_socks_address(reader, reply[3])
    await reader.readexactly(2)


async def _http_connect(stream: _Stream, upstream: Upstream, host: str, port: int) -> None:
    reader, writer = stream
    authority = f"[{host}]:{port}" if ':' in host else f"{host}:{port}"
    lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
    if upstream.basic_auth:
        lines.append(upstream.basic_auth)
    writer.write(('\r\n'.join(lines) + '\r\n\r\n').encode('latin-1'))
    status = (await reader.readuntil(b'\r\n\r\n')).split(b'\r\n', 1)[0].decode('latin-1').split(' ', 2)
    if len(status) < 2 or not status[1].startswith('2'):
        raise FirewallError(f"upstream proxy answered {' '.join(status[1:]) or 'nothing'}")


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except (ConnectionError, OSError):
        writer.close()  # the other direction then sees end of stream and stops too


class ScopeFirewall:
    def __init__(self, scope: Scope, receipt: Path, upstream: Optional[str] = None,
                 forbids: Optional[Callable[[str], bool]] = None, required_headers: Sequence[str] = ()):
        self.scope = scope
        self.forbids = forbids or (lambda path: False)
        self.required_headers = [name.lower() for name in required_headers]
        self.receipt = Path(receipt)
        self.upstream = Upstream(upstream) if upstream else None
        self.stage = ''             # set by the pipeline, so each record names the stage that caused it
        self.connections = 0
        self.blocked = 0
        self._allowed_hosts: Dict[str, dict] = {}
        self._blocked_hosts: Dict[str, dict] = {}
        self._blocked_paths: Dict[str, dict] = {}
        self.header_checks = {'checked': 0, 'missing': 0}
        self._tasks: Set[asyncio.Task] = set()
        self._server: Optional[asyncio.AbstractServer] = None
        self._log = None
        self.port = 0

    async def __aenter__(self) -> 'ScopeFirewall':
        self.receipt.parent.mkdir(parents=True, exist_ok=True)
        self._log = open(self.receipt, 'a', encoding='utf-8')
        self._server = await asyncio.start_server(self._serve, '127.0.0.1', 0, limit=_HEAD_LIMIT)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc) -> None:
        self._server.close()
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._log.close()

    def url(self, scheme: str = 'http') -> str:
        return f"{scheme}://127.0.0.1:{self.port}"

    def summary(self) -> dict:
        return {
            'enabled': True,
            'receipt': RECEIPT_NAME,
            'connections': self.connections,
            'hosts': sorted(self._allowed_hosts),
            'contacted': _entries('host', self._allowed_hosts),
            'blocked': _entries('host', self._blocked_hosts),
            'forbidden': _entries('url', self._blocked_paths),
            'header_checks': dict(self.header_checks, required=list(self.required_headers)),
        }

    # -- decisions --------------------------------------------------------

    def _check(self, host: str, port: int, via: str, path: Optional[str] = None,
               headers: Sequence[str] = ()) -> bool:
        """Decide whether host (and, for plain HTTP, path) may be contacted, and write it to the receipt."""
        allowed = self.scope.allows(f"[{host}]" if ':' in host else host)
        record = {'time': datetime.now(timezone.utc).isoformat(timespec='milliseconds'), 'stage': self.stage,
                  'action': 'allowed' if allowed else 'blocked', 'host': host, 'port': port, 'via': via}
        if path is not None:
            record['path'] = path
        if allowed and path is not None and self.forbids(path):
            allowed = False
            record.update(action='blocked', reason='forbidden path')
            self.blocked += 1
            authority = f"{host}:{port}" if port != 80 else host
            _count(self._blocked_paths, f"http://{authority}{path}", self.stage)
        elif allowed:
            self.connections += 1
            _count(self._allowed_hosts, host, self.stage, 'connections')
            if path is not None and self.required_headers:
                present = {line.split(':', 1)[0].strip().lower() for line in headers}
                missing = [name for name in self.required_headers if name not in present]
                self.header_checks['checked'] += 1
                if missing:
                    self.header_checks['missing'] += 1
                record['required_headers'] = 'missing: ' + ', '.join(missing) if missing else 'present'
        elif host in _TOOL_PROBES:
            record['note'] = _TOOL_PROBES[host]
        else:
            self.blocked += 1
            _count(self._blocked_hosts, host, self.stage)
        self._log.write(json.dumps(record) + '\n')
        self._log.flush()
        return allowed

    async def _dial(self, host: str, port: int) -> _Stream:
        """A byte stream to host:port, directly or tunnelled through the upstream proxy."""
        upstream = self.upstream
        if upstream is None:
            return await asyncio.wait_for(asyncio.open_connection(host, port), _TIMEOUT)
        stream = await asyncio.wait_for(self._dial_upstream(), _TIMEOUT)
        try:
            connect = _socks5_connect if upstream.socks else _http_connect
            await asyncio.wait_for(connect(stream, upstream, host, port), _UPSTREAM_TIMEOUT)
        except BaseException:
            stream[1].close()
            raise
        return stream

    async def _dial_upstream(self) -> _Stream:
        upstream = self.upstream
        return await asyncio.open_connection(upstream.host, upstream.port, ssl=True if upstream.tls else None)

    # -- serving ----------------------------------------------------------

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self._tasks.add(task)
        remote: Optional[asyncio.StreamWriter] = None
        try:
            first = await asyncio.wait_for(reader.readexactly(1), _TIMEOUT)
            if first == b'\x05':
                stream = await self._socks(reader, writer)
            else:
                head = first + await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), _TIMEOUT)
                stream = await self._http(head, writer)
            if stream:
                remote = stream[1]
                await asyncio.gather(_pipe(reader, remote), _pipe(stream[0], writer))
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError,
                ConnectionError, OSError, FirewallError, ValueError):
            pass
        finally:
            self._tasks.discard(task)
            for stream_writer in (writer, remote):
                if stream_writer is not None:
                    stream_writer.close()

    async def _open(self, host: str, port: int) -> Optional[_Stream]:
        try:
            return await self._dial(host, port)
        except (asyncio.TimeoutError, OSError, FirewallError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError):
            return None

    async def _socks(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[_Stream]:
        await reader.readexactly((await reader.readexactly(1))[0])
        writer.write(b'\x05\x00')
        _, command, _, kind = await reader.readexactly(4)
        host = await _read_socks_address(reader, kind)
        port = int.from_bytes(await reader.readexactly(2), 'big')

        def reply(code: int) -> None:
            writer.write(bytes([5, code, 0, 1]) + bytes(6))

        if command != 1:
            reply(7)  # only CONNECT is supported
            return None
        if not self._check(host, port, 'socks5'):
            reply(2)  # connection not allowed by ruleset
            return None
        stream = await self._open(host, port)
        reply(0 if stream else 4)
        return stream

    async def _http(self, head: bytes, writer: asyncio.StreamWriter) -> Optional[_Stream]:
        request, *headers = head.decode('latin-1').rstrip('\r\n').split('\r\n')
        method, target, version = request.split(' ', 2)

        def reply(status: str) -> None:
            writer.write(f"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode('latin-1'))

        if method.upper() == 'CONNECT':
            parts = urlsplit('//' + target)
            host, port = parts.hostname, parts.port or 443
            if not host:
                reply('400 Bad Request')
                return None
            if not self._check(host, port, 'connect'):
                reply('403 Forbidden')
                return None
            stream = await self._open(host, port)
            if stream is None:
                reply('502 Bad Gateway')
                return None
            writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            return stream

        parts = urlsplit(target)
        if parts.scheme.lower() != 'http' or not parts.hostname:
            reply('400 Bad Request')
            return None
        host, port = parts.hostname, parts.port or 80
        # A blocked or unreachable host gets no answer at all: an error page from here
        # would be read by the tool as the target's own response.
        if not self._check(host, port, 'http', parts.path or '/', headers):
            return None
        upstream = self.upstream
        try:
            if upstream and not upstream.socks:
                stream = await asyncio.wait_for(self._dial_upstream(), _TIMEOUT)
                extra = [upstream.basic_auth] if upstream.basic_auth else []
            else:
                stream = await self._dial(host, port)
                target, extra = (parts.path or '/') + (f"?{parts.query}" if parts.query else ''), []
        except (asyncio.TimeoutError, OSError, FirewallError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError):
            return None
        stream[1].write(_request_head(method, target, version, headers, extra))
        return stream


def _count(table: Dict[str, dict], key: str, stage: str, counter: str = 'attempts') -> None:
    entry = table.setdefault(key, {counter: 0, 'stages': set()})
    entry[counter] += 1
    entry['stages'].add(stage)


def _entries(name: str, table: Dict[str, dict]) -> List[dict]:
    return [{name: key, **entry, 'stages': sorted(entry['stages'])} for key, entry in sorted(table.items())]


def _request_head(method: str, target: str, version: str, headers: Sequence[str], extra: List[str]) -> bytes:
    """The request as it is sent on: hop-by-hop headers dropped, and one request per connection."""
    kept = [line for line in headers if line.split(':', 1)[0].strip().lower() not in _HOP_HEADERS]
    lines = [f"{method} {target} {version}", *kept, *extra, 'Connection: close']
    return ('\r\n'.join(lines) + '\r\n\r\n').encode('latin-1')
