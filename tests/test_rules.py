from datetime import datetime, timezone

import pytest

from reconic.rules import Rules, RulesError, load_for_program, rules_path

TEXT = """\
# from the program policy
rate-limit: 10
header: X-HackerOne-Research: hacker
forbid: /logout
forbid: /account/*/delete
forbid: /admin/
exclude: blog.example.com
hours: 22:00-06:00
timezone: UTC
"""


def test_parse():
    rules = Rules.parse(TEXT, 'acme.rules')
    assert rules.rate_limit == 10
    assert rules.headers == ['X-HackerOne-Research: hacker'] and rules.header_names() == ['X-HackerOne-Research']
    assert rules.exclude == ['blog.example.com']
    assert rules.to_dict()['hours'] == '22:00-06:00 UTC'
    assert 'hacker' not in str(rules.to_dict())  # header values are not recorded


@pytest.mark.parametrize('line, message', [
    ('forbidd: /logout', 'unknown rule'),
    ('rate-limit: fast', 'whole number'),
    ('rate-limit: 0', 'whole number'),
    ('header: no colon', 'Name: value'),
    ('forbid: logout', "starting with '/'"),
    ('hours: 9-17', '22:00-06:00'),
    ('hours: 10:00-10:00', 'not a usable window'),
    ('timezone: Mars/Olympus', 'unknown time zone'),
    ('exclude:', 'needs a value'),
])
def test_mistakes_are_errors_not_silently_ignored(line, message):
    with pytest.raises(RulesError, match=message):
        Rules.parse(f"rate-limit: 5\n{line}\n", 'acme.rules')
    with pytest.raises(RulesError, match='acme.rules:2'):
        Rules.parse(f"rate-limit: 5\n{line}\n", 'acme.rules')


@pytest.mark.parametrize('url, forbidden', [
    ('https://shop.example.com/logout', True),
    ('https://shop.example.com/LOGOUT?next=/', True),
    ('https://shop.example.com/logout.php', True),
    ('https://shop.example.com/logout/now', True),
    ('https://shop.example.com/%6cogout', True),
    ('https://shop.example.com/logouts', False),
    ('https://shop.example.com/account/42/delete', True),
    ('https://shop.example.com/account/42/edit', False),
    ('https://shop.example.com/admin/users', True),
    ('https://shop.example.com/admin', False),
    ('https://shop.example.com/', False),
    ('/logout', True),
])
def test_forbidden_paths(url, forbidden):
    assert Rules.parse(TEXT).forbids(url) is forbidden


def test_katana_regexes_match_the_same_urls():
    import re
    regexes = Rules.parse(TEXT).url_regexes()
    assert any(re.match(r, 'https://shop.example.com/logout?x=1') for r in regexes)
    assert not any(re.match(r, 'https://shop.example.com/logouts') for r in regexes)
    assert not any(re.match(r, 'https://logout.example.com/') for r in regexes)


def at(hour, minute=0):
    return datetime(2026, 11, 12, hour, minute, tzinfo=timezone.utc)


def test_scan_hours_window():
    overnight = Rules.parse("hours: 22:00-06:00\n")
    assert overnight.window_problem(at(23)) is None and overnight.window_problem(at(5, 59)) is None
    problem = overnight.window_problem(at(14, 30))
    assert 'from 22:00 to 06:00 UTC' in problem and 'opens in 7h30m' in problem
    assert overnight.window_problem(at(6)) is not None
    daytime = Rules.parse("hours: 09:00-17:00\ntimezone: Asia/Tokyo\n")  # UTC+9
    assert daytime.window_problem(at(1)) is None   # 10:00 in Tokyo
    assert 'opens in' in daytime.window_problem(at(10))
    assert Rules().window_problem() is None


def test_program_gets_a_template_once(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
    rules, template = load_for_program('h1', 'acme', 'h1:acme')
    assert template == rules_path('h1', 'acme') == tmp_path / 'reconic' / 'programs' / 'h1-acme.rules'
    assert rules.empty and 'h1:acme' in template.read_text()
    assert Rules.parse(template.read_text()).empty  # the template itself sets nothing
    template.write_text("rate-limit: 3\n")
    rules, template = load_for_program('h1', 'acme', 'h1:acme')
    assert template is None and rules.rate_limit == 3
