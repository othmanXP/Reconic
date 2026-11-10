"""The one place external tools are launched.

Every binary goes through Runner.run, so proxy, auth headers, rate limit,
timeouts, process cleanup and error capture behave the same for all of them.
"""
from __future__ import annotations

import asyncio
import os
import re
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

_VERSION_RE = re.compile(r'(?:current|engine) version:?\s*v?(\d+)\.(\d+)(?:\.(\d+))?', re.I)
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


class ToolError(Exception):
    """A tool could not be run at all (missing, or it cannot honour the options)."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binaries: Tuple[str, ...]
    proxy_flag: Optional[str] = None    # None: the tool cannot be proxied
    header_flag: Optional[str] = None   # None: the tool sends no requests to the target
    rate_flag: Optional[str] = None
    common_flags: Tuple[str, ...] = ('-silent', '-nc', '-duc')
    install: str = ''


@dataclass
class RunOptions:
    proxy: Optional[str] = None
    headers: List[str] = field(default_factory=list)
    rate_limit: Optional[int] = None


@dataclass
class ResolvedTool:
    spec: ToolSpec
    path: str
    version: Tuple[int, int, int]

    @property
    def version_text(self) -> str:
        return '.'.join(str(n) for n in self.version)


@dataclass
class ToolResult:
    tool: str
    stage: str
    returncode: Optional[int]
    timed_out: bool
    duration: float
    stdout_path: Path
    stderr_path: Path

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def lines(self) -> List[str]:
        text = self.stdout_path.read_text(encoding='utf-8', errors='replace')
        return [line.strip() for line in text.splitlines() if line.strip()]

    def stderr_tail(self, count: int = 3) -> str:
        text = _ANSI_RE.sub('', self.stderr_path.read_text(encoding='utf-8', errors='replace'))
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return ' | '.join(lines[-count:])

    def failure(self) -> str:
        tail = self.stderr_tail()
        return f"{self.tool} exited with code {self.returncode}" + (f": {tail}" if tail else "")


def default_search_path() -> List[str]:
    dirs = [d for d in os.environ.get('PATH', '').split(os.pathsep) if d]
    gobin = os.environ.get('GOBIN') or os.path.join(os.environ.get('GOPATH') or os.path.expanduser('~/go'), 'bin')
    if gobin not in dirs:
        dirs.append(gobin)
    return dirs


def _signal_group(proc, sig) -> None:
    try:
        if hasattr(os, 'killpg'):
            os.killpg(proc.pid, sig)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError):
        pass


async def _terminate(proc) -> None:
    """Stop the tool and everything it spawned (headless browsers included)."""
    if proc.returncode is not None:
        return
    _signal_group(proc, signal.SIGTERM)
    try:
        await asyncio.wait_for(proc.wait(), 5)
    except asyncio.TimeoutError:
        _signal_group(proc, getattr(signal, 'SIGKILL', signal.SIGTERM))
        await proc.wait()


def _redact_proxy(url: str) -> str:
    return re.sub(r'//[^/@]+@', '//<redacted>@', url)


class Runner:
    def __init__(self, raw_dir: Path, options: Optional[RunOptions] = None,
                 search_path: Optional[Sequence[str]] = None):
        self.raw_dir = Path(raw_dir)
        self.options = options or RunOptions()
        self.search_path = list(search_path) if search_path is not None else default_search_path()
        self._resolved: Dict[str, Optional[ResolvedTool]] = {}

    async def resolve(self, spec: ToolSpec) -> Optional[ResolvedTool]:
        """Find a binary that really is this tool, checked by its version banner.

        A name match is not enough: the Python `httpx` CLI shadows ProjectDiscovery's.
        """
        if spec.name not in self._resolved:
            found = None
            for name in spec.binaries:
                for directory in self.search_path:
                    path = os.path.join(directory, name)
                    if os.path.isfile(path) and os.access(path, os.X_OK):
                        version = await self._probe_version(path)
                        if version:
                            found = ResolvedTool(spec, path, version)
                            break
                if found:
                    break
            self._resolved[spec.name] = found
        return self._resolved[spec.name]

    def resolved(self) -> Dict[str, dict]:
        return {name: {'path': tool.path, 'version': tool.version_text}
                for name, tool in self._resolved.items() if tool}

    @staticmethod
    async def _probe_version(path: str) -> Optional[Tuple[int, int, int]]:
        try:
            proc = await asyncio.create_subprocess_exec(
                path, '-version',
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError:
            return None
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), 20)
        except asyncio.TimeoutError:
            await _terminate(proc)
            return None
        except BaseException:
            await _terminate(proc)
            raise
        match = _VERSION_RE.search(_ANSI_RE.sub('', output.decode('utf-8', errors='replace')))
        if not match:
            return None
        return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)

    async def run(self, spec: ToolSpec, args: Sequence[str], stage: str, timeout: float) -> ToolResult:
        tool = await self.resolve(spec)
        if tool is None:
            hint = f" Install: {spec.install}" if spec.install else ""
            raise ToolError(f"{spec.name} is not installed (looked for {', '.join(spec.binaries)}).{hint}")

        argv = [tool.path, *args, *spec.common_flags]
        shown = list(argv)
        options = self.options
        if options.proxy:
            if not spec.proxy_flag:
                raise ToolError(f"{spec.name} cannot be routed through a proxy; refusing to run it with a proxy set")
            argv += [spec.proxy_flag, options.proxy]
            shown += [spec.proxy_flag, _redact_proxy(options.proxy)]
        if spec.header_flag:
            for header in options.headers:
                argv += [spec.header_flag, header]
                shown += [spec.header_flag, header.split(':', 1)[0] + ': <redacted>']
        if spec.rate_flag and options.rate_limit:
            argv += [spec.rate_flag, str(options.rate_limit)]
            shown += [spec.rate_flag, str(options.rate_limit)]

        self.raw_dir.mkdir(parents=True, exist_ok=True)
        base = f"{stage}.{spec.name}"
        stdout_path, stderr_path = self.raw_dir / f"{base}.out", self.raw_dir / f"{base}.err"
        (self.raw_dir / f"{base}.cmd").write_text(' '.join(shown) + '\n', encoding='utf-8')

        started = time.monotonic()
        timed_out = False
        with open(stdout_path, 'wb') as out, open(stderr_path, 'wb') as err:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True,
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout)
            except asyncio.TimeoutError:
                timed_out = True
                await _terminate(proc)
            except BaseException:
                await _terminate(proc)
                raise

        return ToolResult(spec.name, stage, proc.returncode, timed_out,
                          time.monotonic() - started, stdout_path, stderr_path)
