"""Command line interface: `reconic scan` and `reconic doctor`."""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from . import __version__
from .banner import print_banner
from .pipeline import TOOLS, Pipeline, ScanConfig, StageReport, failed_stages
from .runner import Runner, RunOptions
from .scope import Scope, host_of

TOR_PROXY = 'socks5://127.0.0.1:9050'
_COLORS = {'red': 31, 'green': 32, 'yellow': 33, 'cyan': 36, 'dim': 2, 'bold': 1}
_SEVERITY_COLORS = {'critical': 'red', 'high': 'red', 'medium': 'yellow'}


def _paint(text: str, color: str) -> str:
    if not sys.stderr.isatty() or 'NO_COLOR' in os.environ:
        return text
    return f"\033[{_COLORS[color]}m{text}\033[0m"


def _say(text: str = '') -> None:
    print(text, file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='reconic', description='Scope-safe recon orchestrator for subfinder, httpx, katana and nuclei.')
    parser.add_argument('--version', action='version', version=f"reconic {__version__}")
    parser.add_argument('--no-banner', action='store_true', help='do not print the banner')
    sub = parser.add_subparsers(dest='command', metavar='{scan,doctor}')

    sub.add_parser('doctor', help='show which tools were found and their versions')

    scan = sub.add_parser(
        'scan', help='run the recon pipeline',
        description='Runs enumerate -> probe -> crawl -> takeover -> nuclei, never leaving the scope.')
    target = scan.add_argument_group('scope')
    target.add_argument('-d', '--domain', action='append', default=[], metavar='DOMAIN',
                        help='domain whose subdomains are in scope and get enumerated (repeatable)')
    target.add_argument('-u', '--host', action='append', default=[], metavar='HOST_OR_URL',
                        help='single host in scope, tested as is with no enumeration (repeatable)')
    target.add_argument('--scope', type=Path, metavar='FILE',
                        help="scope file: one pattern per line, '!' prefix excludes, '#' comments")
    target.add_argument('-x', '--exclude', action='append', default=[], metavar='PATTERN',
                        help='pattern to keep out of scope, e.g. admin.example.com or *.corp.example.com')

    stages = scan.add_argument_group('stages')
    stages.add_argument('--passive', action='store_true',
                        help='enumeration only; nothing is sent to the target')
    stages.add_argument('--no-crawl', action='store_true', help='skip katana')
    stages.add_argument('--no-takeover', action='store_true', help='skip the takeover check')
    stages.add_argument('--no-nuclei', action='store_true', help='skip the nuclei vulnerability scan')
    stages.add_argument('--pick', action='store_true',
                        help='choose which alive hosts to continue with after probing')

    net = scan.add_argument_group('network')
    net.add_argument('--proxy', metavar='URL', help='send every tool through this HTTP/SOCKS5 proxy')
    net.add_argument('--tor', action='store_true', help=f"shorthand for --proxy {TOR_PROXY}")
    net.add_argument('-H', '--header', action='append', default=[], metavar='"Name: value"',
                     help='header sent with every request to the target (repeatable)')
    net.add_argument('--cookie', metavar='COOKIE', help='shorthand for -H "Cookie: COOKIE"')
    net.add_argument('--rate-limit', type=int, metavar='N', help='max requests per second, per tool')
    net.add_argument('--threads', type=int, default=50, metavar='N', help='httpx threads (default 50)')

    tune = scan.add_argument_group('tuning')
    tune.add_argument('--all-sources', action='store_true', help='subfinder: use every source (slower)')
    tune.add_argument('--depth', type=int, default=3, metavar='N', help='crawl depth (default 3)')
    tune.add_argument('--headless', action='store_true', help='katana: crawl with a headless browser')
    tune.add_argument('--crawl-minutes', type=int, default=10, metavar='N',
                      help='katana: max crawl duration per target (default 10)')
    tune.add_argument('--severity', default='critical,high,medium',
                      help='nuclei severities (default critical,high,medium)')
    tune.add_argument('--templates', type=Path, metavar='DIR', help='nuclei: custom templates')
    tune.add_argument('--stage-timeout', type=int, default=60, metavar='MIN',
                      help='hard limit per stage in minutes; the tool is killed after it (default 60)')

    out = scan.add_argument_group('output')
    out.add_argument('-o', '--output-dir', type=Path, default=Path('reconic_output'), metavar='DIR',
                     help='where run directories are created (default ./reconic_output)')
    out.add_argument('-y', '--yes', action='store_true',
                     help='confirm you are authorized to test this scope, without the prompt')
    return parser


def build_scope(args: argparse.Namespace) -> Scope:
    include: List[str] = []
    exclude: List[str] = list(args.exclude)
    for domain in args.domain:
        host = host_of(domain)
        if host is None:
            raise ValueError(f"not a valid domain: {domain!r}")
        include += [host, f"*.{host}"]
    for target in args.host:
        host = host_of(target)
        if host is None:
            raise ValueError(f"not a valid host or URL: {target!r}")
        include.append(host)
    if args.scope:
        file_include, file_exclude = Scope.parse_file(args.scope)
        include += file_include
        exclude += file_exclude
    return Scope(include, exclude)


def build_options(args: argparse.Namespace) -> RunOptions:
    if args.proxy and args.tor:
        raise ValueError("use either --proxy or --tor, not both")
    headers = list(args.header)
    if args.cookie:
        headers.append(f"Cookie: {args.cookie}")
    for header in headers:
        if ':' not in header or not header.split(':', 1)[0].strip():
            raise ValueError(f'header must look like "Name: value": {header!r}')
    if args.rate_limit is not None and args.rate_limit < 1:
        raise ValueError("--rate-limit must be at least 1")
    return RunOptions(proxy=TOR_PROXY if args.tor else args.proxy, headers=headers, rate_limit=args.rate_limit)


def select_hosts(text: str, alive: List[dict]) -> List[dict]:
    """'all', numbers and ranges like '1,3,5-8', or a keyword matched against the URL."""
    text = text.strip().lower()
    if text in ('', 'all', 'a'):
        return list(alive)
    if re.fullmatch(r'[\d,\s-]+', text):
        wanted = set()
        for part in filter(None, (p.strip() for p in text.split(','))):
            low, _, high = part.partition('-')
            if not low.isdigit() or (high and not high.isdigit()):
                return []
            wanted.update(range(int(low), int(high or low) + 1))
        return [entry for index, entry in enumerate(alive, 1) if index in wanted]
    return [entry for entry in alive if text in entry['url'].lower()]


def _pick(alive: List[dict]) -> List[dict]:
    _say()
    for index, entry in enumerate(alive, 1):
        _say(f"  {index:>3}  {entry['url']}  {_paint(str(entry['status'] or ''), 'dim')}  {entry['title'][:50]}")
    while True:
        chosen = select_hosts(input("  Continue with [all | 1,3,5-8 | keyword]: "), alive)
        if chosen:
            _say(f"  {len(chosen)} host(s) selected\n")
            return chosen
        _say(_paint("  nothing matched, try again", 'yellow'))


def _stage_start(name: str, what: str) -> None:
    _say(f"  {_paint('▸', 'cyan')} {name:<10} {_paint(what, 'dim')}")


def _stage_end(report: StageReport) -> None:
    if report.status == 'skipped':
        _say(f"  {_paint('–', 'dim')} {report.name:<10} {_paint('skipped: ' + report.detail, 'dim')}")
        return
    noun = {'enumerate': 'host(s)', 'probe': 'alive', 'crawl': 'endpoint(s)'}.get(report.name, 'finding(s)')
    parts = [f"{report.count} {noun}"]
    if report.out_of_scope:
        parts.append(f"{report.out_of_scope} out of scope dropped")
    parts.append(f"{report.duration:.1f}s")
    if report.status == 'ok':
        _say(f"  {_paint('✓', 'green')} {report.name:<10} {' · '.join(parts)}")
    else:
        _say(f"  {_paint('✗', 'red')} {report.name:<10} {_paint(report.status + ': ' + report.detail, 'red')}")
        _say(f"    {' ' * 10} {_paint(' · '.join(parts), 'dim')}")


async def _doctor() -> int:
    with tempfile.TemporaryDirectory() as scratch:
        runner = Runner(Path(scratch))
        missing = 0
        _say("  Tools")
        for spec in TOOLS:
            tool = await runner.resolve(spec)
            if tool:
                _say(f"  {_paint('✓', 'green')} {spec.name:<10} v{tool.version_text:<9} {_paint(tool.path, 'dim')}")
            else:
                missing += 1
                _say(f"  {_paint('✗', 'red')} {spec.name:<10} not found")
                _say(f"    {' ' * 10} {_paint(spec.install, 'dim')}")
    _say()
    return 1 if missing else 0


def _confirm(scope: Scope, config: ScanConfig, yes: bool) -> bool:
    _say("  Scope")
    for pattern in scope.include:
        _say(f"    {_paint('+', 'green')} {pattern}")
    for pattern in scope.exclude:
        _say(f"    {_paint('-', 'red')} {pattern}")
    if config.options.proxy:
        _say(f"  Proxy       every tool, DNS lookups may still be made locally by the tools")
    if config.options.headers:
        _say(f"  Auth        {len(config.options.headers)} header(s) sent to every in-scope host")
    _say()
    if config.passive or yes:
        return True
    if not sys.stdin.isatty():
        _say(_paint("  Active stages need confirmation: pass --yes if you are authorized to test this scope.", 'red'))
        return False
    answer = input("  Type 'yes' to confirm you are authorized to test everything in this scope: ")
    _say()
    return answer.strip().lower() == 'yes'


def _summary(results: dict, run_dir: Path) -> None:
    _say()
    _say(f"  {len(results['subdomains'])} host(s) · {len(results['alive'])} alive · "
         f"{len(results['endpoints'])} endpoint(s) · {len(results['findings'])} finding(s)")
    for finding in results['findings']:
        severity = finding['severity']
        label = _paint(f"{severity:<8}", _SEVERITY_COLORS.get(severity, 'dim'))
        _say(f"    {label} {finding['template']}  {_paint(finding['matched'], 'dim')}")
    problems = failed_stages(results)
    if problems:
        _say()
        _say(_paint(f"  {len(problems)} stage(s) did not complete; results are partial:", 'red'))
        for name, detail in problems:
            _say(f"    {name}: {detail}")
    _say()
    _say(f"  Results  {run_dir}")
    _say()


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return 2
    if not args.no_banner:
        print_banner()

    try:
        if args.command == 'doctor':
            return asyncio.run(_doctor())

        try:
            scope = build_scope(args)
            options = build_options(args)
        except (ValueError, OSError) as error:
            _say(_paint(f"  error: {error}", 'red'))
            return 2

        config = ScanConfig(
            scope=scope, output_dir=args.output_dir, options=options,
            passive=args.passive, crawl=not args.no_crawl, takeover=not args.no_takeover,
            nuclei=not args.no_nuclei, all_sources=args.all_sources, threads=args.threads,
            depth=args.depth, headless=args.headless, crawl_minutes=args.crawl_minutes,
            severity=args.severity, templates=args.templates, stage_timeout=args.stage_timeout * 60,
        )
        if not _confirm(scope, config, args.yes):
            _say("  Scan cancelled.")
            return 2

        pipeline = Pipeline(config, on_start=_stage_start, on_end=_stage_end,
                            picker=_pick if args.pick and sys.stdin.isatty() else None)
        results = asyncio.run(pipeline.run())
        _summary(results, pipeline.run_dir)
        print(pipeline.run_dir / 'results.json')
        return 1 if failed_stages(results) else 0
    except KeyboardInterrupt:
        _say(_paint("\n  Interrupted; running tools were stopped.", 'yellow'))
        return 130


if __name__ == '__main__':
    sys.exit(main())
