import json

import pytest

from reconic.cli import main
from reconic.store import DB_NAME, Store, StoreError


def stage(name, status='ok', detail=''):
    return {'name': name, 'status': status, 'detail': detail, 'duration': 1.0, 'count': 0, 'out_of_scope': 0}


def results(hosts=(), alive=(), endpoints=(), findings=(), stages=None, target='example.com', scope=None):
    return {
        'reconic_version': 'test', 'target': target,
        'started': '2026-01-01T10:00:00+00:00', 'finished': '2026-01-01T10:05:00+00:00',
        'scope': scope or {'include': ['example.com', '*.example.com'], 'exclude': []},
        'stages': stages or [stage(n) for n in ('enumerate', 'probe', 'crawl', 'takeover', 'nuclei')],
        'subdomains': list(hosts),
        'alive': [{'url': f"https://{h}", 'status': 200, 'title': ''} for h in alive],
        'endpoints': list(endpoints),
        'findings': list(findings),
    }


def finding(template, matched, stage_name='nuclei', severity='high'):
    return {'stage': stage_name, 'template': template, 'matched': matched, 'severity': severity, 'name': template}


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / DB_NAME) as opened:
        yield opened


def keys(entry):
    return [item['key'] for item in entry['added']]


def test_diff_reports_added_and_removed(store, tmp_path):
    first = store.record(results(hosts=['a.example.com', 'b.example.com'], alive=['a.example.com'],
                                 endpoints=['https://a.example.com/login']), tmp_path)
    second = store.record(results(hosts=['a.example.com', 'c.example.com'], alive=['a.example.com', 'c.example.com'],
                                  endpoints=['https://a.example.com/login'],
                                  findings=[finding('exposed-env', 'https://c.example.com/.env'),
                                            finding('s3-takeover', 'c.example.com', 'takeover')]), tmp_path)
    diff = store.diff(first, second)
    kinds = diff['kinds']
    assert keys(kinds['host']) == ['c.example.com'] and kinds['host']['removed'] == ['b.example.com']
    assert keys(kinds['alive']) == ['https://c.example.com'] and kinds['alive']['added'][0]['status'] == 200
    assert kinds['endpoint']['added'] == [] and kinds['endpoint']['removed'] == []
    assert keys(kinds['vuln']) == ['exposed-env https://c.example.com/.env']
    assert kinds['vuln']['added'][0]['severity'] == 'high'
    assert keys(kinds['takeover']) == ['s3-takeover c.example.com']
    assert diff['scope_changed'] is False


def test_reappearing_asset_is_flagged_as_seen_before(store, tmp_path):
    store.record(results(hosts=['a.example.com', 'back.example.com']), tmp_path)
    second = store.record(results(hosts=['a.example.com']), tmp_path)
    third = store.record(results(hosts=['a.example.com', 'back.example.com', 'fresh.example.com']), tmp_path)
    added = {item['key']: item['seen_before'] for item in store.diff(second, third)['kinds']['host']['added']}
    assert added == {'back.example.com': True, 'fresh.example.com': False}


def test_incomplete_stage_is_not_compared(store, tmp_path):
    full = store.record(results(hosts=['a.example.com'], endpoints=['https://a.example.com/x']), tmp_path)
    stages = [stage('enumerate'), stage('probe'), stage('crawl', 'skipped', 'disabled'),
              stage('takeover'), stage('nuclei', 'failed', 'nuclei exited with code 1')]
    partial = store.record(results(hosts=['a.example.com'], stages=stages), tmp_path)
    kinds = store.diff(full, partial)['kinds']
    assert kinds['endpoint']['comparable'] is False and kinds['endpoint']['removed'] == []
    assert 'crawl was skipped (disabled)' in kinds['endpoint']['reason']
    assert kinds['vuln']['comparable'] is False and 'nuclei failed' in kinds['vuln']['reason']
    assert kinds['host']['comparable'] is True


def test_fixed_host_scope_counts_as_complete_enumeration(store, tmp_path):
    stages = [stage('enumerate', 'skipped', 'no wildcard domains in scope')] + [
        stage(n) for n in ('probe', 'crawl', 'takeover', 'nuclei')]
    first = store.record(results(hosts=['app.example.com'], stages=stages), tmp_path)
    second = store.record(results(hosts=['app.example.com'], stages=stages), tmp_path)
    assert store.diff(first, second)['kinds']['host']['comparable'] is True


def test_scope_change_is_flagged(store, tmp_path):
    first = store.record(results(), tmp_path)
    second = store.record(results(scope={'include': ['example.com'], 'exclude': []}), tmp_path)
    assert store.diff(first, second)['scope_changed'] is True


def test_targets_are_kept_apart(store, tmp_path):
    first = store.record(results(hosts=['a.example.com']), tmp_path)
    other = store.record(results(hosts=['a.other.org'], target='other.org'), tmp_path)
    third = store.record(results(hosts=['a.example.com']), tmp_path)
    assert store.targets() == ['example.com', 'other.org']
    assert store.previous_run('example.com', third) == first
    assert store.previous_run('other.org', other) is None
    assert [run['counts']['host'] for run in store.runs('example.com')] == [1, 1]
    with pytest.raises(StoreError, match='different targets'):
        store.diff(first, other)
    with pytest.raises(StoreError, match='no such run'):
        store.diff(first, 99)


# -- through the CLI, with fake tools ---------------------------------------

@pytest.fixture
def cli(fake_tools, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('PATH', fake_tools.dir)
    monkeypatch.setenv('GOBIN', fake_tools.dir)  # keep real tools out of reach
    out_dir = str(tmp_path / 'out')

    def run(*argv):
        code = main(['--no-banner', *argv, '-o', out_dir])
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return run


def test_scan_records_history_and_reports_what_is_new(cli, monkeypatch):
    code, out, err = cli('scan', '-d', 'example.com', '-y')
    assert code == 0
    assert 'Run 1: first recorded run for example.com' in err
    assert out.strip().endswith('results.json')

    monkeypatch.setenv('FAKE_LABELS', 'www,staging')
    code, _, err = cli('scan', '-d', 'example.com', '-y')
    assert code == 0
    assert 'Run 2: new since run 1' in err
    assert '+ host      staging.example.com' in err
    assert '+ alive     https://staging.example.com' in err
    assert '+ 2 endpoint(s)' in err

    code, out, _ = cli('diff', 'example.com')
    assert code == 0
    assert 'run 1' in out and 'run 2' in out
    assert '+ staging.example.com' in out and '- api.example.com' in out
    assert '+ https://staging.example.com/login' in out

    code, out, _ = cli('diff', '--json')
    assert json.loads(out)['kinds']['host']['removed'] == ['admin.example.com', 'api.example.com']

    code, out, _ = cli('runs')
    assert code == 0 and len(out.strip().splitlines()) == 3


def test_failed_stage_shows_as_not_compared(cli, monkeypatch):
    cli('scan', '-d', 'example.com', '-y')
    monkeypatch.setenv('FAKE_FAIL', 'katana')
    code, _, err = cli('scan', '-d', 'example.com', '-y')
    assert code == 1
    assert 'endpoints not compared: crawl failed in run 2' in err
    code, out, _ = cli('diff')
    assert 'not compared: crawl failed in run 2' in out
    code, out, _ = cli('runs')
    assert out.strip().splitlines()[-1].endswith('crawl')


def test_diff_needs_history_and_two_runs(cli):
    code, _, err = cli('diff')
    assert code == 2 and 'no history' in err
    cli('scan', '-u', 'app.example.com', '-y')
    code, _, err = cli('diff')
    assert code == 2 and 'nothing to compare' in err


def test_name_groups_runs_with_different_scopes(cli):
    cli('scan', '-u', 'app.example.com', '--name', 'acme', '-y')
    code, _, err = cli('scan', '-u', 'app.example.com', '-u', 'api.example.com', '--name', 'acme', '-y')
    assert 'Run 2: new since run 1' in err
    assert 'the scope changed between these runs' in err
    assert '+ host      api.example.com' in err
