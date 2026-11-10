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


def test_options():
    options = build_options(parse('-u', 'a.example.com', '--tor', '--cookie', 'sid=1', '-H', 'X-Bug: me'))
    assert options.proxy == TOR_PROXY
    assert options.headers == ['X-Bug: me', 'Cookie: sid=1']
    with pytest.raises(ValueError):
        build_options(parse('-u', 'a.example.com', '--tor', '--proxy', 'http://127.0.0.1:8080'))
    with pytest.raises(ValueError):
        build_options(parse('-u', 'a.example.com', '-H', 'no-colon'))


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
    assert '38;5;' in render_banner(truecolor=False) and '38;2;' not in render_banner(truecolor=False)
