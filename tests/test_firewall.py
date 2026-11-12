import asyncio
import json

import pytest

from reconic.firewall import ScopeFirewall, Upstream
from reconic.scope import Scope

# The stand-in target listens on 127.0.0.1, which is in scope. 'localhost' reaches the
# same server but is out of scope, so a request that gets through would be seen.
SCOPE = Scope(['127.0.0.1'])


class Target:
    """A local server standing in for a target; it records every request that reaches it."""

    async def __aenter__(self):
        self.requests = []
        self.server = await asyncio.start_server(self._serve, '127.0.0.1', 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()

    async def _serve(self, reader, writer):
        try:
            self.requests.append((await reader.readuntil(b'\r\n\r\n')).decode())
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


async def talk(port, *messages):
    """Send each message after the reply to the one before it; return everything received."""
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    received = b''
    for index, message in enumerate(messages):
        writer.write(message)
        await writer.drain()
        if index < len(messages) - 1:
            received += await asyncio.wait_for(reader.read(65536), 5)
    received += await asyncio.wait_for(reader.read(-1), 5)
    writer.close()
    return received


def socks_request(host, port):
    return b'\x05\x01\x00\x03' + bytes([len(host)]) + host.encode() + port.to_bytes(2, 'big')


def receipt(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


GET = b'GET /page HTTP/1.1\r\nHost: target\r\n\r\n'


def test_connect_tunnels_to_an_in_scope_host(tmp_path):
    async def scenario():
        async with Target() as target, ScopeFirewall(SCOPE, tmp_path / 'receipt') as firewall:
            connect = f"CONNECT 127.0.0.1:{target.port} HTTP/1.1\r\n\r\n".encode()
            return await talk(firewall.port, connect, GET), target.requests

    answer, requests = asyncio.run(scenario())
    assert answer.startswith(b'HTTP/1.1 200 Connection established') and answer.endswith(b'ok')
    assert requests == [GET.decode()]


def test_connect_out_of_scope_is_refused_and_never_reaches_the_host(tmp_path):
    async def scenario():
        async with Target() as target, ScopeFirewall(SCOPE, tmp_path / 'receipt') as firewall:
            connect = f"CONNECT localhost:{target.port} HTTP/1.1\r\n\r\n".encode()
            return await talk(firewall.port, connect), target.requests, firewall.summary()

    answer, requests, summary = asyncio.run(scenario())
    assert answer.startswith(b'HTTP/1.1 403')
    assert requests == []
    assert summary['connections'] == 0
    assert summary['blocked'] == [{'host': 'localhost', 'attempts': 1, 'stages': ['']}]


def test_plain_request_is_forwarded_without_proxy_headers(tmp_path):
    async def scenario():
        async with Target() as target, ScopeFirewall(SCOPE, tmp_path / 'receipt') as firewall:
            request = (f"GET http://127.0.0.1:{target.port}/a?b=1 HTTP/1.1\r\nHost: 127.0.0.1:{target.port}\r\n"
                       "Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic c2VjcmV0\r\n"
                       "Cookie: sid=1\r\n\r\n").encode()
            return await talk(firewall.port, request), target.requests

    answer, requests = asyncio.run(scenario())
    assert answer.endswith(b'ok')
    assert requests[0].startswith('GET /a?b=1 HTTP/1.1\r\n')
    assert 'Cookie: sid=1' in requests[0] and 'Connection: close' in requests[0]
    assert 'proxy-' not in requests[0].lower()


def test_plain_request_out_of_scope_gets_no_answer_at_all(tmp_path):
    # An error page from the firewall would be taken for the target's own response.
    async def scenario():
        async with Target() as target, ScopeFirewall(SCOPE, tmp_path / 'receipt') as firewall:
            request = f"GET http://localhost:{target.port}/ HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
            return await talk(firewall.port, request), target.requests, firewall.blocked

    answer, requests, blocked = asyncio.run(scenario())
    assert answer == b'' and requests == [] and blocked == 1


def test_socks5_side_enforces_the_same_scope(tmp_path):
    async def scenario():
        async with Target() as target, ScopeFirewall(SCOPE, tmp_path / 'receipt') as firewall:
            allowed = await talk(firewall.port, b'\x05\x01\x00', socks_request('127.0.0.1', target.port), GET)
            refused = await talk(firewall.port, b'\x05\x01\x00', socks_request('localhost', target.port))
            return allowed, refused, target.requests

    allowed, refused, requests = asyncio.run(scenario())
    assert allowed.startswith(b'\x05\x00\x05\x00') and allowed.endswith(b'ok')
    assert refused.startswith(b'\x05\x00\x05\x02')  # connection not allowed by ruleset
    assert requests == [GET.decode()]


def test_receipt_records_every_decision_with_its_stage(tmp_path):
    async def scenario():
        async with Target() as target, ScopeFirewall(SCOPE, tmp_path / 'receipt') as firewall:
            firewall.stage = 'crawl'
            await talk(firewall.port, f"GET http://127.0.0.1:{target.port}/ HTTP/1.1\r\n\r\n".encode())
            await talk(firewall.port, b"GET http://tracker.other-company.net/p.gif HTTP/1.1\r\n\r\n")
            firewall.stage = 'nuclei'
            await talk(firewall.port, b"CONNECT other-company.net:443 HTTP/1.1\r\n\r\n")
            await talk(firewall.port, b"GET http://burpsuite/cert HTTP/1.1\r\n\r\n")
            return firewall.summary(), firewall.blocked

    summary, blocked = asyncio.run(scenario())
    records = receipt(tmp_path / 'receipt')
    assert [(r['stage'], r['action'], r['host'], r['via']) for r in records] == [
        ('crawl', 'allowed', '127.0.0.1', 'http'),
        ('crawl', 'blocked', 'tracker.other-company.net', 'http'),
        ('nuclei', 'blocked', 'other-company.net', 'connect'),
        ('nuclei', 'blocked', 'burpsuite', 'http'),
    ]
    assert all(record['time'] and record['port'] for record in records)
    # katana's own Burp probe is refused and recorded, but is not an attempt to leave the scope
    assert 'note' in records[-1] and blocked == 2
    assert summary['hosts'] == ['127.0.0.1']
    assert [(entry['host'], entry['stages']) for entry in summary['blocked']] == [
        ('other-company.net', ['nuclei']), ('tracker.other-company.net', ['crawl'])]


@pytest.mark.parametrize('scheme', ['http', 'socks5'])
def test_allowed_traffic_is_chained_through_the_users_proxy(tmp_path, scheme):
    async def scenario():
        async with Target() as target, ScopeFirewall(SCOPE, tmp_path / 'upstream') as upstream:
            async with ScopeFirewall(SCOPE, tmp_path / 'receipt', upstream=upstream.url(scheme)) as firewall:
                tunnelled = await talk(firewall.port, f"CONNECT 127.0.0.1:{target.port} HTTP/1.1\r\n\r\n".encode(), GET)
                plain = await talk(firewall.port, f"GET http://127.0.0.1:{target.port}/x HTTP/1.1\r\n\r\n".encode())
                await talk(firewall.port, f"CONNECT localhost:{target.port} HTTP/1.1\r\n\r\n".encode())
                return tunnelled, plain, len(target.requests), upstream.connections, upstream.blocked

    tunnelled, plain, reached, through_upstream, upstream_blocked = asyncio.run(scenario())
    assert tunnelled.endswith(b'ok') and plain.endswith(b'ok')
    assert reached == 2 and through_upstream == 2  # nothing went round the proxy
    assert upstream_blocked == 0                   # the refused host was never even asked for


def test_upstream_proxy_urls():
    proxy = Upstream('http://user:p%40ss@127.0.0.1:8080')
    assert (proxy.host, proxy.port, proxy.socks) == ('127.0.0.1', 8080, False)
    assert proxy.basic_auth == 'Proxy-Authorization: Basic dXNlcjpwQHNz'
    assert Upstream('socks5://127.0.0.1').port == 1080 and Upstream('socks5h://127.0.0.1:9050').socks
    with pytest.raises(ValueError, match='--no-firewall'):
        Upstream('socks4://127.0.0.1:1080')


def test_forbidden_path_on_plain_http_is_refused_and_headers_are_checked(tmp_path):
    from reconic.rules import Rules
    rules = Rules.parse("forbid: /logout\nheader: X-Bug-Bounty: me\n")

    async def scenario():
        async with Target() as target, ScopeFirewall(SCOPE, tmp_path / 'receipt', forbids=rules.forbids,
                                                     required_headers=rules.header_names()) as firewall:
            firewall.stage = 'crawl'
            base = f"http://127.0.0.1:{target.port}"
            ok = await talk(firewall.port, f"GET {base}/home HTTP/1.1\r\nX-Bug-Bounty: me\r\n\r\n".encode())
            bare = await talk(firewall.port, f"GET {base}/about HTTP/1.1\r\n\r\n".encode())
            refused = await talk(firewall.port, f"GET {base}/LogOut?next=/ HTTP/1.1\r\nX-Bug-Bounty: me\r\n\r\n".encode())
            return (ok, bare, refused), target.requests, firewall.summary(), firewall.blocked

    (ok, bare, refused), requests, summary, blocked = asyncio.run(scenario())
    assert ok.endswith(b'ok') and bare.endswith(b'ok') and refused == b''
    assert [r.split(' ')[1] for r in requests] == ['/home', '/about']  # /LogOut never reached the target
    assert blocked == 1 and summary['blocked'] == []
    assert [(e['url'].split('/', 3)[3], e['attempts'], e['stages']) for e in summary['forbidden']] == [
        ('LogOut', 1, ['crawl'])]
    assert summary['header_checks'] == {'checked': 2, 'missing': 1, 'required': ['x-bug-bounty']}
    assert summary['contacted'] == [{'host': '127.0.0.1', 'connections': 2, 'stages': ['crawl']}]
    records = receipt(tmp_path / 'receipt')
    assert [(r['action'], r['path'], r.get('reason'), r.get('required_headers')) for r in records] == [
        ('allowed', '/home', None, 'present'),
        ('allowed', '/about', None, 'missing: x-bug-bounty'),
        ('blocked', '/LogOut', 'forbidden path', None),
    ]
