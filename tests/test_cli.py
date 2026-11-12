import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from reconic.banner import render_banner
from reconic.cli import TOR_PROXY, build_options, build_parser, build_scope, main, select_hosts

ALIVE = [{'url': f"https://{name}.example.com"} for name in ('www', 'api', 'staging', 'api-v2')]


def parse(*argv):
    return build_parser().parse_args(['scan', *argv])


def test_domain_flag_covers_apex_and_subdomains():
    scope = build_scope(parse('-d', 'Example.com', '-x', 'admin.example.com'))
    assert scope.include == ['example.com', '*.example.com']
    assert scope.exclude == ['admin.example.com']


def test_host_flag_stays_on_that_host():
    scope = build_scope(parse('-u', 'https://app.example.com/dashboard'))
    assert scope.include == ['app.example.com']
    assert not scope.allows('example.com')


def test_scope_is_required():
    with pytest.raises(ValueError):
        build_scope(parse())


def test_scope_with_nothing_to_start_from_is_refused(tmp_path):
    scope_file = tmp_path / 'scope.txt'
    scope_file.write_text("example.*\n")
    with pytest.raises(ValueError, match='nothing to start from'):
        build_scope(parse('--scope', str(scope_file)))
    scope_file.write_text("example.*\n10.0.0.0/30\n")
    assert build_scope(parse('--scope', str(scope_file))).seeds() == ['10.0.0.1', '10.0.0.2']


def test_options():
    options = build_options(parse('-u', 'a.example.com', '--tor', '--cookie', 'sid=1', '-H', 'X-Bug: me'))
    assert options.proxy == TOR_PROXY
    assert options.headers == ['X-Bug: me', 'Cookie: sid=1']
    with pytest.raises(ValueError):
        build_options(parse('-u', 'a.example.com', '--tor', '--proxy', 'http://127.0.0.1:8080'))
    with pytest.raises(ValueError):
        build_options(parse('-u', 'a.example.com', '-H', 'no-colon'))
    # the firewall has to be able to chain to the proxy; without the firewall any proxy is the tools' business
    with pytest.raises(ValueError, match='--no-firewall'):
        build_options(parse('-u', 'a.example.com', '--proxy', 'socks4://127.0.0.1:1080'))
    assert build_options(parse('-u', 'a.example.com', '--proxy', 'socks4://127.0.0.1:1080', '--no-firewall')).proxy


def test_select_hosts():
    assert select_hosts('all', ALIVE) == ALIVE
    assert select_hosts('', ALIVE) == ALIVE
    assert [a['url'] for a in select_hosts('1, 3-4', ALIVE)] == [
        'https://www.example.com', 'https://staging.example.com', 'https://api-v2.example.com']
    assert len(select_hosts('api', ALIVE)) == 2
    assert select_hosts('99', ALIVE) == []
    assert select_hosts('nomatch', ALIVE) == []


def test_active_scan_refuses_without_confirmation(tmp_path, capsys):
    code = main(['--no-banner', 'scan', '-u', 'app.example.com', '-o', str(tmp_path / 'out')])
    assert code == 2
    assert 'pass --yes' in capsys.readouterr().err
    assert not (tmp_path / 'out').exists()


def test_banner_lines_align_and_fall_back():
    plain = render_banner(color=False).splitlines()
    assert {len(line) for line in plain[-3:]} == {55}
    assert max(len(line) for line in plain) == 55
    assert render_banner(unicode_ok=False).startswith('RECONIC v')
    assert render_banner(width=40).count('\n') == 1
    assert '\033[' not in render_banner(color=False)
    colored = render_banner(color=True)
    assert '\033[1m' in colored and '38;2;' not in colored and '38;5;' not in colored  # theme colours only


@pytest.mark.skipif(os.name == 'nt', reason='needs POSIX signals')
def test_ctrl_c_saves_the_run_and_records_it(fake_tools, tmp_path, capsys):
    out = tmp_path / 'out'
    env = dict(os.environ, PATH=fake_tools.dir, GOPATH=str(tmp_path / 'go'), FAKE_HANG='katana')
    env.pop('GOBIN', None)
    process = subprocess.Popen(
        [sys.executable, '-m', 'reconic', '--no-banner', 'scan', '-u', 'app.example.com', '-y', '-o', str(out)],
        cwd=Path(__file__).parent.parent, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        preexec_fn=lambda: signal.signal(signal.SIGINT, signal.default_int_handler))
    try:
        deadline = time.monotonic() + 60
        while not any(path.stat().st_size for path in out.glob('*/*/raw/crawl.katana.out')):
            assert process.poll() is None and time.monotonic() < deadline, process.stderr.read()
            time.sleep(0.05)
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=60)
    finally:
        process.kill()

    assert process.returncode == 130
    assert 'partial results were saved' in stderr
    results = json.loads(Path(stdout.strip()).read_text())
    assert results['interrupted'] and [a['url'] for a in results['alive']] == ['https://app.example.com']
    assert {s['name']: s['status'] for s in results['stages']}['crawl'] == 'interrupted'
    assert main(['runs', '-o', str(out), '--json']) == 0
    recorded = json.loads(capsys.readouterr().out)
    assert len(recorded) == 1 and recorded[0]['stages']['crawl']['status'] == 'interrupted'
