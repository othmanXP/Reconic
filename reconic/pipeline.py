"""Recon pipeline: enumerate -> resolve -> probe -> crawl -> takeover -> nuclei.

Scope is applied to the input and the output of every stage, and the tools
that contact targets run behind the scope firewall. Each run writes into its
own directory, so results can never be mixed with an earlier run.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from . import __version__
from .firewall import RECEIPT_NAME, ScopeFirewall
from .runner import Runner, RunOptions, ToolError, ToolSpec
from .scope import Scope, is_address

SUBFINDER = ToolSpec(
    'subfinder', ('subfinder',), proxy_flag='-proxy', rate_flag='-rl',
    install='go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest')
DNSX = ToolSpec(
    'dnsx', ('dnsx',), rate_flag='-rl', optional=True,
    install='go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest')
HTTPX = ToolSpec(
    'httpx', ('httpx', 'httpx-toolkit'), proxy_flag='-http-proxy', header_flag='-H', rate_flag='-rl',
    firewalled=True,
    install='go install github.com/projectdiscovery/httpx/cmd/httpx@latest')
KATANA = ToolSpec(
    'katana', ('katana',), proxy_flag='-proxy', header_flag='-H', rate_flag='-rl', firewalled=True,
    install='go install github.com/projectdiscovery/katana/cmd/katana@latest')
# No -duc for nuclei: its own update check is what keeps templates current.
NUCLEI = ToolSpec(
    'nuclei', ('nuclei',), proxy_flag='-proxy', header_flag='-H', rate_flag='-rl',
    common_flags=('-silent', '-nc'), firewalled=True,
    install='go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest')

TOOLS = (SUBFINDER, DNSX, HTTPX, KATANA, NUCLEI)
STAGES = ('enumerate', 'resolve', 'probe', 'crawl', 'takeover', 'nuclei')
INCOMPLETE = ('failed', 'timeout', 'interrupted')  # stage statuses that make a run partial


@dataclass
class ScanConfig:
    scope: Scope
    name: Optional[str] = None  # history key; defaults to the first scope pattern
    output_dir: Path = Path('reconic_output')
    options: RunOptions = field(default_factory=RunOptions)
    passive: bool = False
    dns_only: bool = False
    resolve: bool = True
    crawl: bool = True
    takeover: bool = True
    nuclei: bool = True
    firewall: bool = True
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
    status: str = 'ok'          # ok | failed | timeout | interrupted | skipped
    detail: str = ''
    duration: float = 0.0
    count: int = 0
    out_of_scope: int = 0
    blocked: int = 0            # out-of-scope connections the firewall refused during the stage


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
        self.interrupted = False
        self.results: Optional[dict] = None
        self.hosts: List[str] = []
        self.resolved: List[dict] = []
        self.alive: List[dict] = []
        self.endpoints: List[str] = []
        self.findings: List[dict] = []

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

    def _interrupt(self) -> None:
        """Take note of Ctrl-C and carry on just long enough to save what the run has."""
        self.interrupted = True
        task = asyncio.current_task()
        if hasattr(task, 'uncancel'):
            task.uncancel()

    async def _tool(self, report: StageReport, spec: ToolSpec, args: Sequence[str]) -> List[str]:
        """Run a tool for a stage; record failure or timeout on the report, return its output lines."""
        timeout = self.config.stage_timeout
        firewall = self.runner.firewall
        if firewall:
            firewall.stage = report.name
        blocked, started = firewall.blocked if firewall else 0, time.monotonic()
        try:
            result = await self.runner.run(spec, args, report.name, timeout)
        except ToolError as error:
            report.status, report.detail = 'failed', str(error)
            return []
        except asyncio.CancelledError:
            self._interrupt()
            report.status, report.detail = 'interrupted', f"{spec.name} was stopped; partial results kept"
            report.duration = time.monotonic() - started
            return self.runner.partial_lines(spec, report.name)
        finally:
            if firewall:
                report.blocked = firewall.blocked - blocked
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
        seeds = scope.seeds()
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

    async def _resolve(self, hosts: List[str]) -> Tuple[List[str], List[dict]]:
        """Drop hosts with no address so later stages don't waste requests on dead names.

        Returns the hosts to probe and the DNS records found. Whenever resolution
        cannot be trusted (skipped, failed, timed out) every host is passed on.
        Addresses have nothing to resolve and are always passed on.
        """
        names = [host for host in hosts if not is_address(host)]
        why = ''
        if not self.config.resolve:
            why = 'disabled'
        elif not names:
            why = 'only addresses in scope'
        elif self.config.options.proxy:
            why = 'dnsx cannot use a proxy; every host is passed on'
        elif await self.runner.resolve(DNSX) is None:
            why = 'dnsx is not installed; every host is passed on'
        if why:
            self._skip('resolve', why)
            return hosts, []
        self.on_start('resolve', f"dnsx on {len(names)} host(s)")
        report = StageReport('resolve')
        args = ['-l', self._input_file('resolve', names), '-a', '-aaaa', '-cname', '-resp', '-j']
        wanted, records = set(names), {}
        for item in _json_lines(await self._tool(report, DNSX, args)):
            host = (item.get('host') or '').lower().rstrip('.')
            addresses = (item.get('a') or []) + (item.get('aaaa') or [])
            if host in wanted and addresses:
                records[host] = {'host': host, 'addresses': addresses, 'cname': item.get('cname') or []}
        resolved = [records[host] for host in hosts if host in records]
        report.count = len(resolved)
        self._finish(report)
        if report.status != 'ok':
            return hosts, resolved
        return [host for host in hosts if host in records or is_address(host)], resolved

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

    async def _stages(self) -> None:
        cfg = self.config
        self.hosts = await self._enumerate()
        if self.interrupted:
            return
        if cfg.passive or not self.hosts:
            for name in STAGES[1:]:
                self._skip(name, 'passive mode' if cfg.passive else 'no in-scope hosts')
            return

        live_hosts, self.resolved = await self._resolve(self.hosts)
        if self.interrupted:
            return
        if cfg.dns_only:
            for name in STAGES[2:]:
                self._skip(name, 'DNS only')
            return

        if live_hosts:
            self.alive = await self._probe(live_hosts)
            if self.interrupted:
                return
        else:
            self._skip('probe', 'no host resolves')
        if self.alive and self.picker:
            self.alive = self.picker(self.alive)
        urls = [entry['url'] for entry in self.alive]

        if not cfg.crawl:
            self._skip('crawl', 'disabled')
        elif not urls:
            self._skip('crawl', 'no alive hosts')
        else:
            self.endpoints = await self._crawl(urls)
            if self.interrupted:
                return

        names = [host for host in self.hosts if not is_address(host)]  # an address has no DNS record to dangle
        if not cfg.takeover:
            self._skip('takeover', 'disabled')
        elif not names:
            self._skip('takeover', 'no hostnames in scope')
        else:
            self.findings += await self._nuclei('takeover', names, ['-tags', 'takeover'])
            if self.interrupted:
                return

        if not cfg.nuclei:
            self._skip('nuclei', 'disabled')
        elif not urls:
            self._skip('nuclei', 'no alive hosts')
        else:
            extra = ['-s', cfg.severity]
            if cfg.templates:
                extra += ['-t', str(cfg.templates)]
            self.findings += await self._nuclei('nuclei', urls, extra)

    async def run(self) -> dict:
        """Run the stages and save the results. Ctrl-C stops the run but what it has is still saved."""
        cfg = self.config
        started = datetime.now(timezone.utc)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        firewall = {'enabled': False}
        try:
            if cfg.firewall and not (cfg.passive or cfg.dns_only):
                async with ScopeFirewall(cfg.scope, self.run_dir / RECEIPT_NAME, cfg.options.proxy) as running:
                    self.runner.firewall = running
                    try:
                        await self._stages()
                    finally:
                        self.runner.firewall = None
                        firewall = running.summary()
            else:
                await self._stages()
        except asyncio.CancelledError:
            self._interrupt()
        reported = {report.name for report in self.reports}
        for name in STAGES:
            if name not in reported:
                self._skip(name, 'interrupted')

        unique, seen = [], set()
        for finding in self.findings:
            key = (finding['template'], finding['matched'])
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        self.results = results = {
            'reconic_version': __version__,
            'target': self.target,
            'started': started.isoformat(timespec='seconds'),
            'finished': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'interrupted': self.interrupted,
            'scope': cfg.scope.to_dict(),
            'options': {
                'passive': cfg.passive,
                'proxy': bool(cfg.options.proxy),
                'authenticated': bool(cfg.options.headers),
                'rate_limit': cfg.options.rate_limit,
            },
            'firewall': firewall,
            'tools': self.runner.resolved(),
            'stages': [asdict(report) for report in self.reports],
            'subdomains': self.hosts,
            'resolved': self.resolved,
            'alive': self.alive,
            'endpoints': self.endpoints,
            'findings': unique,
        }
        self._write(results)
        return results

    def _write(self, results: dict) -> None:
        out = self.run_dir
        (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
        (out / 'subdomains.txt').write_text(''.join(f"{h}\n" for h in results['subdomains']), encoding='utf-8')
        (out / 'resolved.txt').write_text(
            ''.join(f"{r['host']} {' '.join(r['addresses'])}\n" for r in results['resolved']), encoding='utf-8')
        (out / 'alive.txt').write_text(''.join(f"{a['url']}\n" for a in results['alive']), encoding='utf-8')
        (out / 'endpoints.txt').write_text(''.join(f"{e}\n" for e in results['endpoints']), encoding='utf-8')
        (out / 'findings.jsonl').write_text(
            ''.join(json.dumps(f) + '\n' for f in results['findings']), encoding='utf-8')


def failed_stages(results: dict) -> List[Tuple[str, str]]:
    return [(s['name'], s['detail']) for s in results['stages'] if s['status'] in INCOMPLETE]
