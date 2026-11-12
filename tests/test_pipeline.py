import asyncio
import http.server
import json
import threading

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


def proxies(fake_tools):
    """The proxy each tool was started with, or None."""
    given = {}
    for call in fake_tools.calls():
        flag = next((f for f in ('-http-proxy', '-proxy') if f in call['args']), None)
        given[call['tool']] = call['args'][call['args'].index(flag) + 1] if flag else None
    return given


def test_proxy_reaches_every_tool(fake_tools, tmp_path):
    proxy = 'socks5://127.0.0.1:9050'
    scan(fake_tools, tmp_path, domain_scope(), options=RunOptions(proxy=proxy), firewall=False)
    given = proxies(fake_tools)
    assert set(given) == {'subfinder', 'httpx', 'katana', 'nuclei'}
    assert set(given.values()) == {proxy}


def test_tools_that_contact_targets_run_behind_the_firewall(fake_tools, tmp_path):
    _, results = scan(fake_tools, tmp_path, domain_scope())
    given = proxies(fake_tools)
    assert given['subfinder'] is None and given['dnsx'] is None  # they never contact the target
    assert given['httpx'].startswith('http://127.0.0.1:')
    assert given['httpx'] == given['katana'] == given['nuclei']
    assert results['firewall']['enabled'] and results['firewall']['blocked'] == []


def test_firewall_chains_to_the_users_proxy(fake_tools, tmp_path):
    proxy = 'socks5://127.0.0.1:9050'
    scan(fake_tools, tmp_path, domain_scope(), options=RunOptions(proxy=proxy))
    given = proxies(fake_tools)
    assert given['subfinder'] == proxy
    # the SOCKS5 side, so that traffic which is not HTTP cannot go round the user's proxy
    assert given['httpx'].startswith('socks5://127.0.0.1:') and given['httpx'] != proxy
    assert given['httpx'] == given['katana'] == given['nuclei']


def test_firewall_can_be_turned_off_and_is_not_started_for_passive_runs(fake_tools, tmp_path):
    _, results = scan(fake_tools, tmp_path, domain_scope(), firewall=False)
    assert set(proxies(fake_tools).values()) == {None}
    assert results['firewall'] == {'enabled': False}
    pipeline, results = scan(fake_tools, tmp_path, domain_scope(), dns_only=True)
    assert results['firewall'] == {'enabled': False}


def test_firewall_stops_a_tool_from_leaving_scope(fake_tools, tmp_path, monkeypatch):
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_port
    # 'localhost' is the same server, but only 127.0.0.1 is in scope
    monkeypatch.setenv('FAKE_FETCH', f"http://127.0.0.1:{port}/in-scope,http://localhost:{port}/out-of-scope")
    try:
        pipeline, results = scan(fake_tools, tmp_path, Scope(['127.0.0.1']))
    finally:
        server.shutdown()

    assert hits == ['/in-scope']
    assert stage(results, 'crawl')['blocked'] == 1
    assert results['firewall']['hosts'] == ['127.0.0.1']
    assert results['firewall']['blocked'] == [{'host': 'localhost', 'attempts': 1, 'stages': ['crawl']}]
    receipt = [json.loads(line) for line in (pipeline.run_dir / 'scope_receipt.jsonl').read_text().splitlines()]
    assert [(r['stage'], r['action'], r['host']) for r in receipt] == [
        ('crawl', 'allowed', '127.0.0.1'), ('crawl', 'blocked', 'localhost')]


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


def test_resolve_drops_dead_hosts_before_probing(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_LABELS', 'www,dead1,dead2')
    pipeline, results = scan(fake_tools, tmp_path, Scope(['*.example.com']))
    assert results['subdomains'] == ['dead1.example.com', 'dead2.example.com', 'www.example.com']
    assert [r['host'] for r in results['resolved']] == ['www.example.com']
    assert stage(results, 'resolve')['count'] == 1
    assert (pipeline.run_dir / 'raw' / 'probe.input.txt').read_text().split() == ['www.example.com']
    # the takeover check still sees names that no longer resolve: that is where dangling records live
    assert 'dead1.example.com' in (pipeline.run_dir / 'raw' / 'takeover.input.txt').read_text()


def test_missing_dnsx_is_skipped_not_fatal(fake_tools, tmp_path):
    (tmp_path / 'bin' / 'dnsx').unlink()
    _, results = scan(fake_tools, tmp_path, domain_scope())
    assert stage(results, 'resolve')['status'] == 'skipped'
    assert len(results['alive']) == 3 and failed_stages(results) == []


def test_failed_resolve_passes_every_host_on(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_FAIL', 'dnsx')
    _, results = scan(fake_tools, tmp_path, domain_scope())
    assert stage(results, 'resolve')['status'] == 'failed'
    assert len(results['alive']) == 3


def test_proxy_skips_resolve_instead_of_leaking_dns(fake_tools, tmp_path):
    _, results = scan(fake_tools, tmp_path, domain_scope(), options=RunOptions(proxy='socks5://127.0.0.1:9050'))
    assert stage(results, 'resolve')['status'] == 'skipped'
    assert 'dnsx' not in [call['tool'] for call in fake_tools.calls()]


def test_dns_only_sends_no_http(fake_tools, tmp_path):
    _, results = scan(fake_tools, tmp_path, domain_scope(), dns_only=True)
    assert [call['tool'] for call in fake_tools.calls()] == ['subfinder', 'dnsx']
    assert len(results['resolved']) == 3
    assert stage(results, 'probe')['detail'] == 'DNS only'


def test_no_host_resolving_skips_probe(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_LABELS', 'dead1')
    _, results = scan(fake_tools, tmp_path, Scope(['*.example.com']))
    assert stage(results, 'probe')['detail'] == 'no host resolves'
    assert 'httpx' not in [call['tool'] for call in fake_tools.calls()]


def test_interrupt_saves_what_the_run_has(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_HANG', 'katana')
    config = ScanConfig(scope=domain_scope(), output_dir=tmp_path / 'out')
    pipeline = Pipeline(config, runner=Runner(tmp_path / 'unused', search_path=[fake_tools.dir]))

    async def interrupted_run():
        task = asyncio.ensure_future(pipeline.run())
        output = pipeline.run_dir / 'raw' / 'crawl.katana.out'
        while not (output.exists() and output.stat().st_size):
            await asyncio.sleep(0.05)
        task.cancel()  # what Ctrl-C does to the run
        return await task

    results = asyncio.run(interrupted_run())
    assert results['interrupted'] and pipeline.results is results
    assert len(results['alive']) == 3                      # the stages that finished are kept
    assert stage(results, 'crawl')['status'] == 'interrupted'
    assert results['endpoints'] == ['partial.example.com']  # and so is what the stopped tool had written
    assert [stage(results, name)['detail'] for name in ('takeover', 'nuclei')] == ['interrupted'] * 2
    assert 'nuclei' not in [call['tool'] for call in fake_tools.calls()]
    assert [name for name, _ in failed_stages(results)] == ['crawl']
    assert json.loads((pipeline.run_dir / 'results.json').read_text())['interrupted']


def test_network_scope_is_expanded_into_hosts(fake_tools, tmp_path):
    pipeline, results = scan(fake_tools, tmp_path, Scope(['192.0.2.0/30'], ['192.0.2.2']))
    assert results['subdomains'] == ['192.0.2.1']
    assert stage(results, 'resolve')['detail'] == 'only addresses in scope'
    assert [a['url'] for a in results['alive']] == ['https://192.0.2.1']
    assert len(results['endpoints']) == 2
    assert stage(results, 'takeover')['detail'] == 'no hostnames in scope'
    assert stage(results, 'nuclei')['status'] == 'ok' and failed_stages(results) == []


def test_addresses_skip_dns_but_are_still_probed(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_LABELS', 'www,dead1')
    pipeline, results = scan(fake_tools, tmp_path, Scope(['*.example.com', '192.0.2.7']))
    raw = pipeline.run_dir / 'raw'
    assert (raw / 'resolve.input.txt').read_text().split() == ['dead1.example.com', 'www.example.com']
    assert (raw / 'probe.input.txt').read_text().split() == ['192.0.2.7', 'www.example.com']
    assert '192.0.2.7' not in (raw / 'takeover.input.txt').read_text()


def test_wildcard_inside_a_label_enumerates_its_domain(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_LABELS', 'www,api-v2,api-eu')
    pipeline, results = scan(fake_tools, tmp_path, Scope(['api-*.example.com']))
    assert (pipeline.run_dir / 'raw' / 'enumerate.input.txt').read_text().split() == ['example.com']
    assert results['subdomains'] == ['api-eu.example.com', 'api-v2.example.com']
    assert stage(results, 'enumerate')['out_of_scope'] == 2  # www and the foreign host
