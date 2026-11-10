"""Recon pipeline: enumerate -> probe -> crawl -> takeover -> nuclei.

Scope is applied to the input and the output of every stage. Each run writes
into its own directory, so results can never be mixed with an earlier run.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from . import __version__
from .runner import Runner, RunOptions, ToolError, ToolSpec
from .scope import Scope

SUBFINDER = ToolSpec(
    'subfinder', ('subfinder',), proxy_flag='-proxy', rate_flag='-rl',
    install='go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest')
HTTPX = ToolSpec(
    'httpx', ('httpx', 'httpx-toolkit'), proxy_flag='-http-proxy', header_flag='-H', rate_flag='-rl',
    install='go install github.com/projectdiscovery/httpx/cmd/httpx@latest')
KATANA = ToolSpec(
    'katana', ('katana',), proxy_flag='-proxy', header_flag='-H', rate_flag='-rl',
    install='go install github.com/projectdiscovery/katana/cmd/katana@latest')
# No -duc for nuclei: its own update check is what keeps templates current.
NUCLEI = ToolSpec(
    'nuclei', ('nuclei',), proxy_flag='-proxy', header_flag='-H', rate_flag='-rl',
    common_flags=('-silent', '-nc'),
    install='go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest')

TOOLS = (SUBFINDER, HTTPX, KATANA, NUCLEI)
STAGES = ('enumerate', 'probe', 'crawl', 'takeover', 'nuclei')


@dataclass
class ScanConfig:
    scope: Scope
    name: Optional[str] = None  # history key; defaults to the first scope pattern
    output_dir: Path = Path('reconic_output')
    options: RunOptions = field(default_factory=RunOptions)
    passive: bool = False
    crawl: bool = True
    takeover: bool = True
    nuclei: bool = True
    all_sources: bool = False
    threads: int = 50
    depth: int = 3
    headless: bool = False
    crawl_minutes: int = 10
    severity: str = 'critical,high,medium'
    templates: Optional[Path] = None
    stage_timeout: float = 3600.0


@dataclass
class StageReport:
    name: str
    status: str = 'ok'          # ok | failed | timeout | skipped
    detail: str = ''
    duration: float = 0.0
    count: int = 0
    out_of_scope: int = 0


def _json_lines(lines: Sequence[str]) -> List[dict]:
    items = []
    for line in lines:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            items.append(item)
    return items


class Pipeline:
    def __init__(self, config: ScanConfig, runner: Optional[Runner] = None,
                 on_start: Optional[Callable[[str, str], None]] = None,
                 on_end: Optional[Callable[[StageReport], None]] = None,
                 picker: Optional[Callable[[List[dict]], List[dict]]] = None):
        self.config = config
        label = re.sub(r'[^a-z0-9.-]+', '_', (config.name or config.scope.include[0]).lower().lstrip('*.'))
        label = self.target = label.strip('.') or 'scan'
        stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        self.run_dir = Path(config.output_dir) / label / stamp
        suffix = 2
        while self.run_dir.exists():
            self.run_dir = Path(config.output_dir) / label / f"{stamp}-{suffix}"
            suffix += 1
        self.runner = runner or Runner(self.run_dir / 'raw', config.options)
        self.runner.raw_dir = self.run_dir / 'raw'
        self.on_start = on_start or (lambda name, what: None)
        self.on_end = on_end or (lambda report: None)
        self.picker = picker
        self.reports: List[StageReport] = []

    # -- helpers ----------------------------------------------------------

    def _input_file(self, stage: str, lines: Sequence[str]) -> str:
        raw = self.run_dir / 'raw'
        raw.mkdir(parents=True, exist_ok=True)
        path = raw / f"{stage}.input.txt"
        path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return str(path)

    def _finish(self, report: StageReport) -> None:
        self.reports.append(report)
        self.on_end(report)

    def _skip(self, name: str, why: str) -> None:
        self._finish(StageReport(name, 'skipped', why))

    async def _tool(self, report: StageReport, spec: ToolSpec, args: Sequence[str]) -> List[str]:
        """Run a tool for a stage; record failure or timeout on the report, return its output lines."""
        timeout = self.config.stage_timeout
        try:
            result = await self.runner.run(spec, args, report.name, timeout)
        except ToolError as error:
            report.status, report.detail = 'failed', str(error)
            return []
        report.duration = result.duration
        if result.timed_out:
            report.status = 'timeout'
            report.detail = f"{spec.name} stopped after {timeout:.0f}s; partial results kept"
        elif not result.ok:
            report.status, report.detail = 'failed', result.failure()
        return result.lines()

    # -- stages -----------------------------------------------------------

    async def _enumerate(self) -> List[str]:
        scope = self.config.scope
        roots = scope.enumeration_roots()
        seeds = scope.exact_hosts()
        if not roots:
            self._skip('enumerate', 'no wildcard domains in scope')
            return seeds
        self.on_start('enumerate', f"subfinder on {len(roots)} domain(s)")
        report = StageReport('enumerate')
        args = ['-dL', self._input_file('enumerate', roots)]
        if self.config.all_sources:
            args.append('-all')
        found = [line.lower().rstrip('.') for line in await self._tool(report, SUBFINDER, args)]
        kept, report.out_of_scope = scope.split(found)
        hosts = sorted(set(seeds) | set(kept))
        report.count = len(hosts)
        self._finish(report)
        return hosts

    async def _probe(self, hosts: List[str]) -> List[dict]:
        self.on_start('probe', f"httpx on {len(hosts)} host(s)")
        report = StageReport('probe')
        # No redirect following: a redirect can lead off-scope. The Location header is recorded instead.
        args = ['-l', self._input_file('probe', hosts), '-j', '-sc', '-title', '-td', '-location',
                '-t', str(self.config.threads), '-timeout', '10']
        alive, seen = [], set()
        for item in _json_lines(await self._tool(report, HTTPX, args)):
            url = item.get('url')
            if not url or url in seen:
                continue
            seen.add(url)
            if not self.config.scope.allows(url):
                report.out_of_scope += 1
                continue
            alive.append({
                'url': url,
                'host': item.get('input') or url,
                'status': item.get('status_code'),
                'title': item.get('title') or '',
                'tech': item.get('tech') or [],
                'location': item.get('location') or '',
            })
        alive.sort(key=lambda entry: entry['url'])
        report.count = len(alive)
        self._finish(report)
        return alive

    async def _crawl(self, urls: List[str]) -> List[str]:
        cfg = self.config
        self.on_start('crawl', f"katana on {len(urls)} URL(s), depth {cfg.depth}")
        report = StageReport('crawl')
        args = ['-list', self._input_file('crawl', urls), '-d', str(cfg.depth), '-jc',
                '-ct', f"{cfg.crawl_minutes}m"]
        if cfg.depth >= 3:
            args += ['-kf', 'all']  # robots.txt and sitemap.xml; katana wants depth 3+ for these
        if cfg.headless:
            args.append('-hl')
        regexes = cfg.scope.url_regexes()
        if regexes is None:
            args += ['-fs', 'fqdn']
        else:
            for regex in regexes[0]:
                args += ['-cs', regex]
            for regex in regexes[1]:
                args += ['-cos', regex]
        kept, report.out_of_scope = cfg.scope.split(await self._tool(report, KATANA, args))
        endpoints = sorted(kept)
        report.count = len(endpoints)
        self._finish(report)
        return endpoints

    async def _nuclei(self, stage: str, targets: List[str], extra: Sequence[str]) -> List[dict]:
        self.on_start(stage, f"nuclei on {len(targets)} target(s)")
        report = StageReport(stage)
        tool = await self.runner.resolve(NUCLEI)
        modern = tool is None or tool.version[0] >= 3
        args = ['-l', self._input_file(stage, targets), '-jsonl' if modern else '-json', *extra]
        if modern:
            args.append('-or')
        findings = []
        for item in _json_lines(await self._tool(report, NUCLEI, args)):
            info = item.get('info') or {}
            matched = item.get('matched-at') or item.get('host') or ''
            if matched and not self.config.scope.allows(matched):
                report.out_of_scope += 1
                continue
            findings.append({
                'stage': stage,
                'template': item.get('template-id') or '',
                'name': info.get('name') or '',
                'severity': (info.get('severity') or 'unknown').lower(),
                'matched': matched,
                'type': item.get('type') or '',
                'extracted': item.get('extracted-results') or [],
            })
        report.count = len(findings)
        self._finish(report)
        return findings

    # -- run --------------------------------------------------------------

    async def run(self) -> dict:
        cfg = self.config
        started = datetime.now(timezone.utc)
        self.run_dir.mkdir(parents=True, exist_ok=True)

        hosts = await self._enumerate()
        alive: List[dict] = []
        endpoints: List[str] = []
        findings: List[dict] = []

        blocked = 'passive mode' if cfg.passive else ('no in-scope hosts' if not hosts else '')
        if blocked:
            for name in STAGES[1:]:
                self._skip(name, blocked)
        else:
            alive = await self._probe(hosts)
            if alive and self.picker:
                alive = self.picker(alive)
            urls = [entry['url'] for entry in alive]

            if not cfg.crawl:
                self._skip('crawl', 'disabled')
            elif not urls:
                self._skip('crawl', 'no alive hosts')
            else:
                endpoints = await self._crawl(urls)

            if not cfg.takeover:
                self._skip('takeover', 'disabled')
            else:
                findings += await self._nuclei('takeover', hosts, ['-tags', 'takeover'])

            if not cfg.nuclei:
                self._skip('nuclei', 'disabled')
            elif not urls:
                self._skip('nuclei', 'no alive hosts')
            else:
                extra = ['-s', cfg.severity]
                if cfg.templates:
                    extra += ['-t', str(cfg.templates)]
                findings += await self._nuclei('nuclei', urls, extra)

        unique, seen = [], set()
        for finding in findings:
            key = (finding['template'], finding['matched'])
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        results = {
            'reconic_version': __version__,
            'target': self.target,
            'started': started.isoformat(timespec='seconds'),
            'finished': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'scope': cfg.scope.to_dict(),
            'options': {
                'passive': cfg.passive,
                'proxy': bool(cfg.options.proxy),
                'authenticated': bool(cfg.options.headers),
                'rate_limit': cfg.options.rate_limit,
            },
            'tools': self.runner.resolved(),
            'stages': [asdict(report) for report in self.reports],
            'subdomains': hosts,
            'alive': alive,
            'endpoints': endpoints,
            'findings': unique,
        }
        self._write(results)
        return results

    def _write(self, results: dict) -> None:
        out = self.run_dir
        (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
        (out / 'subdomains.txt').write_text(''.join(f"{h}\n" for h in results['subdomains']), encoding='utf-8')
        (out / 'alive.txt').write_text(''.join(f"{a['url']}\n" for a in results['alive']), encoding='utf-8')
        (out / 'endpoints.txt').write_text(''.join(f"{e}\n" for e in results['endpoints']), encoding='utf-8')
        (out / 'findings.jsonl').write_text(
            ''.join(json.dumps(f) + '\n' for f in results['findings']), encoding='utf-8')


def failed_stages(results: dict) -> List[Tuple[str, str]]:
    return [(s['name'], s['detail']) for s in results['stages'] if s['status'] in ('failed', 'timeout')]
