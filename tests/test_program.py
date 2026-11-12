import base64
import http.server
import json
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from reconic.program import ProgramError, fetch_h1, import_program, parse_program, read_assets


def asset(identifier, kind='URL', in_scope=True):
    return {'asset_identifier': identifier, 'asset_type': kind, 'eligible_for_submission': in_scope}


def read(*assets):
    return read_assets(list(assets))


def notes(result):
    return {note['asset']: note['note'] for note in result['notes']}


def test_parse_program():
    assert parse_program('h1:security') == ('h1', 'security')
    assert parse_program('hackerone:acme_corp') == ('h1', 'acme_corp')
    for bad in ('security', 'bugcrowd:acme', 'h1:', 'h1:../../etc', 'h1:a/b'):
        with pytest.raises(ValueError):
            parse_program(bad)


def test_plain_entries_become_patterns():
    result = read(asset('https://app.example.com/'), asset('*.example.com', 'WILDCARD'),
                  asset('API.Example.com:8443'), asset('10.0.0.0/24', 'CIDR'), asset('192.0.2.7', 'IP_ADDRESS'),
                  asset('https://*.shop.example.com/*', 'WILDCARD'))
    assert result['include'] == ['app.example.com', '*.example.com', 'api.example.com:8443', '10.0.0.0/24',
                                 '192.0.2.7/32', '*.shop.example.com']
    assert result['notes'] == []


def test_messy_entries():
    result = read(asset('a.example.com, b.example.com; c.example.com'),
                  asset('www.example.com (main site)'),
                  asset('192.0.2.1-192.0.2.6', 'IP_ADDRESS'))
    assert result['include'] == ['a.example.com', 'b.example.com', 'c.example.com', 'www.example.com',
                                 '192.0.2.1/32', '192.0.2.2/31', '192.0.2.4/31', '192.0.2.6/32']


def test_star_without_a_dot_is_read_narrowly():
    # '*example.com' as a glob would also match attacker-example.com
    result = read(asset('*example.com', 'WILDCARD'))
    assert result['include'] == ['example.com', '*.example.com']
    assert 'read as example.com and *.example.com' in notes(result)['*example.com']


def test_non_web_assets_are_skipped_with_a_note():
    result = read(asset('com.example.app', 'GOOGLE_PLAY_APP_ID'), asset('123456', 'APPLE_STORE_APP_ID'),
                  asset('github.com/example/repo', 'SOURCE_CODE'), asset('app.example.com'))
    assert result['include'] == ['app.example.com']
    assert notes(result)['com.example.app'] == 'skipped: not a web asset (GOOGLE_PLAY_APP_ID)'
    assert len(result['notes']) == 3


def test_entries_that_cannot_be_read_exactly_are_never_guessed():
    result = read(asset('Any host on example.com', 'OTHER'), asset('Any host on example.com', 'DOMAIN'),
                  asset('*.com', 'WILDCARD'), asset('*.*', 'WILDCARD'), asset('app.example.com'))
    assert result['include'] == ['app.example.com']
    assert notes(result)['*.com'].startswith("skipped: could not read '*.com'")


def test_a_path_restricted_url_is_not_widened_to_its_host():
    result = read(asset('https://example.com/api/'), asset('https://example.com/*'), asset('shop.example.com/'))
    assert result['include'] == ['example.com', 'shop.example.com']  # from the unrestricted entries only
    assert 'only /api/ is in scope' in notes(result)['https://example.com/api/']


def test_out_of_scope_entries_become_exclusions():
    result = read(asset('*.example.com', 'WILDCARD'),
                  asset('admin.example.com', in_scope=False),
                  asset('https://blog.example.com/wp-admin', in_scope=False),
                  asset('com.example.app', 'GOOGLE_PLAY_APP_ID', in_scope=False),
                  asset('every staging server', 'URL', in_scope=False))
    assert result['include'] == ['*.example.com']
    assert result['exclude'] == ['admin.example.com', 'blog.example.com']  # the whole host, which is narrower
    by_asset = {note['asset']: note for note in result['notes']}
    assert 'whole host is kept out' in by_asset['https://blog.example.com/wp-admin']['note']
    assert 'com.example.app' not in by_asset  # out of scope and not a web asset: nothing to say
    # an exclusion that could not be read is a risk, so it is a warning
    assert by_asset['every staging server']['warn'] and 'NOT excluded' in by_asset['every staging server']['note']


class FakeHackerOne:
    """A local stand-in for the HackerOne API serving structured scopes two to a page."""

    def __init__(self, assets, status=200):
        self.requests = []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parts = urlsplit(self.path)
                fake.requests.append((parts.path, self.headers.get('Authorization')))
                if status != 200:
                    self.send_response(status)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                page = int(parse_qs(parts.query)['page[number]'][0])
                chunk = assets[(page - 1) * 2:page * 2]
                body = {'data': [{'id': str(i), 'type': 'structured-scope', 'attributes': a}
                                 for i, a in enumerate(chunk)],
                        'links': {'next': 'more'} if page * 2 < len(assets) else {}}
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.api = f"http://127.0.0.1:{self.server.server_port}/v1"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()


ASSETS = [asset('*.example.com', 'WILDCARD'), asset('app.example.org'),
          asset('admin.example.com', in_scope=False), asset('com.example.app', 'GOOGLE_PLAY_APP_ID'),
          asset('www.example.net')]


def test_fetch_follows_pages_and_authenticates():
    with FakeHackerOne(ASSETS) as fake:
        assets = fetch_h1('acme', 'hacker', 's3cret', api=fake.api)
    assert assets == ASSETS
    assert len(fake.requests) == 3
    assert {path for path, _ in fake.requests} == {'/v1/hackers/programs/acme/structured_scopes'}
    assert fake.requests[0][1] == 'Basic ' + base64.b64encode(b'hacker:s3cret').decode()


@pytest.mark.parametrize('status, message', [(401, 'rejected the API credentials'), (404, 'no such program')])
def test_fetch_errors_are_explained(status, message):
    with FakeHackerOne(ASSETS, status=status) as fake:
        with pytest.raises(ProgramError, match=message):
            fetch_h1('acme', 'hacker', 'wrong', api=fake.api)


def test_import_needs_credentials(monkeypatch):
    monkeypatch.delenv('HACKERONE_API_USERNAME', raising=False)
    monkeypatch.delenv('HACKERONE_API_TOKEN', raising=False)
    with pytest.raises(ProgramError, match='HACKERONE_API_TOKEN'):
        import_program('h1:acme', api='http://127.0.0.1:9')


def test_import_keeps_raw_assets_and_refuses_a_program_with_nothing_to_scan(monkeypatch):
    monkeypatch.setenv('HACKERONE_API_USERNAME', 'hacker')
    monkeypatch.setenv('HACKERONE_API_TOKEN', 's3cret')
    with FakeHackerOne(ASSETS) as fake:
        program = import_program('h1:acme', api=fake.api)
    assert program['id'] == 'h1:acme' and program['assets'] == ASSETS
    assert program['include'] == ['*.example.com', 'app.example.org', 'www.example.net']
    assert program['exclude'] == ['admin.example.com']
    with FakeHackerOne([asset('com.example.app', 'GOOGLE_PLAY_APP_ID')]) as fake:
        with pytest.raises(ProgramError, match='no web asset'):
            import_program('h1:acme', api=fake.api)
