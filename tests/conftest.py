import json
import os
import stat
import sys
from pathlib import Path

import pytest

FAKE_SOURCE = Path(__file__).with_name('fake_tool.py')


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
    """A directory of fake tool binaries plus a reader for the invocation log."""
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    log = tmp_path / 'invocations.jsonl'
    monkeypatch.setenv('FAKE_LOG', str(log))
    for variable in ('FAKE_FAIL', 'FAKE_FAIL_STDOUT', 'FAKE_HANG', 'FAKE_IMPOSTOR', 'FAKE_LABELS', 'FAKE_FETCH',
                     'no_proxy', 'NO_PROXY'):
        monkeypatch.delenv(variable, raising=False)

    def install(*names):
        for name in names:
            path = bin_dir / name
            path.write_text(f"#!{sys.executable}\n" + FAKE_SOURCE.read_text(encoding='utf-8'), encoding='utf-8')
            path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def calls():
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text(encoding='utf-8').splitlines()]

    install('subfinder', 'dnsx', 'httpx', 'katana', 'nuclei')
    return type('FakeTools', (), {'dir': str(bin_dir), 'install': staticmethod(install),
                                  'calls': staticmethod(calls)})
