import asyncio
import os
import time

import pytest

from reconic.pipeline import HTTPX, KATANA, NUCLEI, SUBFINDER
from reconic.runner import Runner, RunOptions, ToolError, ToolSpec


def make_runner(fake_tools, tmp_path, **options):
    return Runner(tmp_path / 'raw', RunOptions(**options), search_path=[fake_tools.dir])


def run(coro):
    return asyncio.run(coro)


def write_list(tmp_path, lines):
    path = tmp_path / 'list.txt'
    path.write_text('\n'.join(lines) + '\n')
    return str(path)


def test_resolve_reads_version(fake_tools, tmp_path):
    tool = run(make_runner(fake_tools, tmp_path).resolve(NUCLEI))
    assert tool.version == (3, 9, 0)
    assert tool.path == os.path.join(fake_tools.dir, 'nuclei')


def test_resolve_rejects_impostor_and_falls_back(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_IMPOSTOR', 'httpx')
    runner = make_runner(fake_tools, tmp_path)
    assert run(runner.resolve(HTTPX)) is None

    fake_tools.install('httpx-toolkit')
    tool = run(make_runner(fake_tools, tmp_path).resolve(HTTPX))
    assert os.path.basename(tool.path) == 'httpx-toolkit'


def test_missing_tool_is_an_error_with_install_hint(tmp_path):
    runner = Runner(tmp_path / 'raw', search_path=[str(tmp_path)])
    with pytest.raises(ToolError, match='subfinder is not installed.*go install'):
        run(runner.run(SUBFINDER, [], 'enumerate', 10))


def test_success_captures_output(fake_tools, tmp_path):
    runner = make_runner(fake_tools, tmp_path)
    result = run(runner.run(SUBFINDER, ['-dL', write_list(tmp_path, ['example.com'])], 'enumerate', 30))
    assert result.ok
    assert 'www.example.com' in result.lines()


def test_nonzero_exit_is_reported_with_stderr(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_FAIL', 'subfinder')
    result = run(make_runner(fake_tools, tmp_path).run(SUBFINDER, ['-dL', 'x'], 'enumerate', 30))
    assert not result.ok
    assert result.returncode == 3
    assert 'boom: simulated failure' in result.failure()


def test_error_printed_on_stdout_is_still_reported(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_FAIL_STDOUT', 'katana')
    result = run(make_runner(fake_tools, tmp_path).run(KATANA, ['-list', 'x'], 'crawl', 30))
    assert 'invalid value for flag -x' in result.failure()


def test_timeout_kills_the_tool_and_keeps_partial_output(fake_tools, tmp_path, monkeypatch):
    monkeypatch.setenv('FAKE_HANG', 'subfinder')
    started = time.monotonic()
    result = run(make_runner(fake_tools, tmp_path).run(SUBFINDER, ['-dL', 'x'], 'enumerate', 1.5))
    assert result.timed_out and not result.ok
    assert time.monotonic() - started < 15
    assert result.returncode is not None  # the process is gone, not orphaned
    assert result.lines() == ['partial.example.com']


def test_proxy_headers_and_rate_limit_reach_the_tool(fake_tools, tmp_path):
    runner = make_runner(fake_tools, tmp_path, proxy='socks5://127.0.0.1:9050',
                         headers=['Cookie: session=secret'], rate_limit=20)
    run(runner.run(HTTPX, ['-l', write_list(tmp_path, ['a.example.com'])], 'probe', 30))
    args = fake_tools.calls()[-1]['args']
    assert args[args.index('-http-proxy') + 1] == 'socks5://127.0.0.1:9050'
    assert args[args.index('-H') + 1] == 'Cookie: session=secret'
    assert args[args.index('-rl') + 1] == '20'


def test_headers_are_not_sent_to_third_party_sources(fake_tools, tmp_path):
    runner = make_runner(fake_tools, tmp_path, headers=['Cookie: session=secret'])
    run(runner.run(SUBFINDER, ['-dL', write_list(tmp_path, ['example.com'])], 'enumerate', 30))
    assert 'Cookie: session=secret' not in fake_tools.calls()[-1]['args']


def test_tool_that_cannot_be_proxied_refuses_to_run(fake_tools, tmp_path):
    unproxied = ToolSpec('subfinder', ('subfinder',), proxy_flag=None)
    runner = make_runner(fake_tools, tmp_path, proxy='http://127.0.0.1:8080')
    with pytest.raises(ToolError, match='cannot be routed through a proxy'):
        run(runner.run(unproxied, [], 'enumerate', 10))
    assert fake_tools.calls() == []


def test_command_record_redacts_secrets(fake_tools, tmp_path):
    runner = make_runner(fake_tools, tmp_path, proxy='http://user:hunter2@127.0.0.1:8080',
                         headers=['Authorization: Bearer abc123'])
    run(runner.run(HTTPX, ['-l', write_list(tmp_path, ['a.example.com'])], 'probe', 30))
    recorded = (tmp_path / 'raw' / 'probe.httpx.cmd').read_text()
    assert 'hunter2' not in recorded and 'abc123' not in recorded
    assert 'Authorization: <redacted>' in recorded
