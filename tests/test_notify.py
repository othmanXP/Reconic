import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from reconic.cli import main
from reconic.notify import (MAX_LENGTH, NotifyError, build_message, check_url, first_run_message, payload_for,
                            send)


@pytest.fixture
def webhook():
    """A local webhook that records what it receives; `status` sets the reply code."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            received.append(json.loads(body))
            self.send_response(server.status)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(('127.0.0.1', 0), Handler)
    server.status = 204
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.url = f"http://127.0.0.1:{server.server_port}/hook"
    server.received = received
    yield server
    server.shutdown()
    thread.join()


def item(key, **data):
    return {'key': key, 'seen_before': False, **data}


def test_message_lists_new_items():
    text = build_message('example.com', 7, [
        ('host', item('new.example.com')),
        ('alive', item('https://new.example.com', status=200)),
        ('vuln', item('exposed-env https://new.example.com/.env', severity='high')),
    ], new_endpoints=4)
    assert text.splitlines() == [
        'Reconic: example.com run 7, 7 new',
        '+ host new.example.com',
        '+ alive https://new.example.com  [200]',
        '+ vuln [high] exposed-env https://new.example.com/.env',
        '+ 4 endpoint(s)',
    ]


def test_no_message_when_nothing_is_new():
    assert build_message('example.com', 7, [], 0) is None


def test_long_messages_are_cut_with_a_count():
    items = [('host', item(f"host-{n:04d}.example.com")) for n in range(500)]
    text = build_message('example.com', 2, items, 0)
    assert len(text) < MAX_LENGTH + 100
    assert 'more: reconic diff example.com' in text.splitlines()[-1]


def test_first_run_sends_totals_and_findings_only():
    results = {'subdomains': ['a', 'b'], 'alive': [{}], 'endpoints': ['x'] * 9,
               'findings': [{'stage': 'takeover', 'severity': 'high', 'template': 's3-takeover', 'matched': 'a'}]}
    text = first_run_message('example.com', 1, results)
    assert '2 host(s), 1 alive, 9 endpoint(s), 1 finding(s)' in text
    assert text.splitlines()[1:] == ['+ takeover [high] s3-takeover a']


def test_payload_shape_follows_the_service():
    assert payload_for('https://discord.com/api/webhooks/1/abc', 'hi', 't', 1) == {'content': 'hi'}
    assert payload_for('https://hooks.slack.com/services/T/B/x', 'hi', 't', 1) == {'text': 'hi'}
    assert payload_for('https://example.org/hook', 'hi', 't', 1) == {'text': 'hi', 'target': 't', 'run': 1}
    # a lookalike host gets the generic shape, not Discord's
    assert 'content' not in payload_for('https://discord.com.evil.net/x', 'hi', 't', 1)


def test_check_url():
    assert check_url('https://example.org/hook') == 'https://example.org/hook'
    for bad in ('file:///etc/passwd', 'example.org/hook', 'ftp://example.org'):
        with pytest.raises(ValueError):
            check_url(bad)


def test_send_and_errors(webhook):
    send(webhook.url, {'text': 'hello'})
    assert webhook.received == [{'text': 'hello'}]
    webhook.status = 500
    with pytest.raises(NotifyError, match='HTTP 500'):
        send(webhook.url, {'text': 'again'})
    with pytest.raises(NotifyError, match='unreachable'):
        send('http://127.0.0.1:9/hook', {'text': 'nobody home'}, timeout=3)


def test_scan_notifies_only_when_something_is_new(fake_tools, tmp_path, monkeypatch, capsys, webhook):
    monkeypatch.setenv('PATH', fake_tools.dir)
    monkeypatch.setenv('GOBIN', fake_tools.dir)
    monkeypatch.delenv('RECONIC_NOTIFY', raising=False)
    base = ['--no-banner', 'scan', '-d', 'example.com', '-y', '-o', str(tmp_path / 'out')]

    assert main(base + ['--notify', webhook.url]) == 0
    assert 'first run: 4 host(s), 4 alive' in webhook.received[-1]['text']
    assert 'Notified 127.0.0.1' in capsys.readouterr().err

    monkeypatch.setenv('RECONIC_NOTIFY', webhook.url)  # the environment variable works too
    assert main(base) == 0
    assert len(webhook.received) == 1
    assert 'no notification was sent' in capsys.readouterr().err

    monkeypatch.setenv('FAKE_LABELS', 'www,api,admin,staging')
    assert main(base) == 0
    text = webhook.received[-1]['text']
    assert '+ host staging.example.com' in text and '+ alive https://staging.example.com' in text
    assert '+ resolved staging.example.com' not in text  # already announced as a new host

    webhook.status = 500
    monkeypatch.setenv('FAKE_LABELS', 'www,api,admin,staging,beta')
    assert main(base) == 0  # a failed notification does not fail the scan
    assert 'failed: webhook answered HTTP 500' in capsys.readouterr().err


def test_bad_webhook_url_is_rejected_before_scanning(tmp_path, capsys):
    code = main(['--no-banner', 'scan', '-u', 'a.example.com', '-y', '--notify', 'not-a-url',
                 '-o', str(tmp_path / 'out')])
    assert code == 2 and 'must be http(s)' in capsys.readouterr().err
    assert not (tmp_path / 'out').exists()
