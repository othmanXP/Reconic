import asyncio
import json

from reconic.pipeline import Pipeline, ScanConfig, failed_stages
from reconic.runner import Runner, RunOptions
from reconic.scope import Scope


def scan(fake_tools, tmp_path, scope, picker=None, **settings):
    options = settings.pop('options', RunOptions())
    config = ScanConfig(scope=scope, output_dir=tmp_path / 'out', options=options, **settings)
    runner = Runner(tmp_path / 'unused', options, search_path=[fake_tools.dir])
    pipeline = Pipeline(config, runner=runner, picker=picker)
    return pipeline, asyncio.run(pipeline.run())


def stage(results, name):
    return next(s for s in results['stages'] if s['name'] == name)


def domain_scope():
    return Scope(['example.com', '*.example.com'], ['admin.example.com'])


def test_full_run_stays_in_scope(fake_tools, tmp_path):
    pipeline, results = scan(fake_tools, tmp_path, domain_scope())

    assert results['subdomains'] == ['api.example.com', 'example.com', 'www.example.com']
    assert stage(results, 'enumerate')['out_of_scope'] == 2  # the excluded host and the foreign one
    assert [a['url'] for a in results['alive']] == [
        'https://api.example.com', 'https://example.com', 'https://www.example.com']
    assert 'https://www.example.com/login' in results['endpoints']
    assert not any('other-company' in e for e in results['endpoints'])
    assert stage(results, 'crawl')['out_of_scope'] == 1
    assert sorted(f['template'] for f in results['findings']) == ['exposed-git-config', 'github-takeover']
    assert stage(results, 'nuclei')['out_of_scope'] == 1
    assert failed_stages(results) == []

    # nothing excluded or foreign was ever handed to a tool that contacts targets
    raw = pipeline.run_dir / 'raw'
    for name in ('probe', 'crawl', 'takeover', 'nuclei'):
        handed = (raw / f"{name}.input.txt").read_text()
        assert 'admin.example.com' not in handed and 'other-company' not in handed

    saved = json.loads((pipeline.run_dir / 'results.json').read_text())
    assert saved['findings'] == results['findings']
    assert (pipeline.run_dir / 'alive.txt').read_text().splitlines()[0] == 'https://api.example.com'


def test_single_host_is_not_widened_to_its_domain(fake_tools, tmp_path):
    _, results = scan(fake_tools, tmp_path, Scope(['app.example.com']))
    assert stage(results, 'enumerate')['status'] == 'skipped'
    assert results['subdomains'] == ['app.example.com']
    assert 'subfinder' not in [call['tool'] for call in fake_tools.calls()]


def test_crawler_gets_scope_regexes(fake_tools, tmp_path):
    scan(fake_tools, tmp_path, domain_scope())
    args = next(call['args'] for call in fake_tools.calls() if call['tool'] == 'katana')
    assert args.count('-cs') == 2 and args.count('-cos') == 1


def test_passive_mode_only_enumerates(fake_tools, tmp_path):
    _, results = scan(fake_tools, tmp_path, domain_scope(), passive=True)
    assert [call['tool'] for call in fake_tools.calls()] == ['subfinder']
    assert len(results['subdomains']) == 3
    assert all(stage(results, name)['status'] == 'skipped' for name in ('probe', 'crawl', 'takeover', 'nuclei'))


def test_proxy_reaches_every_tool(fake_tools, tmp_path):
    proxy = 'socks5://127.0.0.1:9050'
    scan(fake_tools, tmp_path, domain_scope(), options=RunOptions(proxy=proxy))
    calls = fake_tools.calls()
    assert {call['tool'] for call in calls} == {'subfinder', 'httpx', 'katana', 'nuclei'}
    assert all(proxy in call['args'] for call in calls)


def test_failed_tool_is_reported_not_hidden(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_FAIL', 'nuclei')
    _, results = scan(fake_tools, tmp_path, domain_scope())
    assert stage(results, 'nuclei')['status'] == 'failed'
    assert 'boom: simulated failure' in stage(results, 'nuclei')['detail']
    assert results['findings'] == []
    assert len(results['endpoints']) > 0  # earlier stages are kept
    assert {name for name, _ in failed_stages(results)} == {'takeover', 'nuclei'}


def test_failed_probe_stops_active_stages_that_need_urls(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_FAIL', 'httpx')
    _, results = scan(fake_tools, tmp_path, domain_scope(), takeover=False)
    assert stage(results, 'probe')['status'] == 'failed'
    assert stage(results, 'crawl')['detail'] == 'no alive hosts'
    assert stage(results, 'nuclei')['detail'] == 'no alive hosts'


def test_timeout_keeps_partial_results(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_HANG', 'subfinder')
    _, results = scan(fake_tools, tmp_path, domain_scope(), passive=True, stage_timeout=1.5)
    assert stage(results, 'enumerate')['status'] == 'timeout'
    assert 'partial.example.com' in results['subdomains']


def test_picker_narrows_later_stages(fake_tools, tmp_path):
    _, results = scan(fake_tools, tmp_path, domain_scope(),
                      picker=lambda alive: [a for a in alive if 'api' in a['url']])
    assert [a['url'] for a in results['alive']] == ['https://api.example.com']
    assert all(e.startswith('https://api.example.com') for e in results['endpoints'])


def test_runs_never_share_a_directory(fake_tools, tmp_path):
    first, _ = scan(fake_tools, tmp_path, Scope(['a.example.com']))
    second, _ = scan(fake_tools, tmp_path, Scope(['a.example.com']))
    assert first.run_dir != second.run_dir
    assert (first.run_dir / 'results.json').exists() and (second.run_dir / 'results.json').exists()
