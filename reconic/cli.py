"""Command line interface: `reconic scan`, `diff`, `runs` and `doctor`."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from typing import List, Optional, Tuple

from . import __version__
from .banner import print_banner
from .firewall import Upstream
from .notify import (NotifyError, build_message, check_url, describe, first_run_message, payload_for,
                     send)
from .pipeline import INCOMPLETE, TOOLS, Pipeline, ScanConfig, StageReport, failed_stages
from .program import ProgramError, import_program, parse_program
from .receipt import RECEIPT_MD
from .rules import Rules, load_for_program
from .runner import Runner, RunOptions
from .scope import Scope, host_of
from .store import DB_NAME, KINDS, Store, StoreError, highlights

TOR_PROXY = 'socks5://127.0.0.1:9050'
_COLORS = {'red': 31, 'green': 32, 'yellow': 33, 'cyan': 36, 'dim': 2, 'bold': 1}
_SEVERITY_COLORS = {'critical': 'red', 'high': 'red', 'medium': 'yellow'}


_KIND_LABELS = {'host': 'hosts', 'resolved': 'resolving', 'alive': 'alive', 'endpoint': 'endpoints', 'takeover': 'takeovers',
                'vuln': 'vulns'}


def _paint(text: str, color: str, stream=None) -> str:
    if not (stream or sys.stderr).isatty() or 'NO_COLOR' in os.environ:
        return text
    return f"\033[{_COLORS[color]}m{text}\033[0m"


def _say(text: str = '') -> None:
    print(text, file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='reconic', description='Scope-safe recon orchestrator for subfinder, dnsx, httpx, katana and nuclei.')
    parser.add_argument('--version', action='version', version=f"reconic {__version__}")
    parser.add_argument('--no-banner', action='store_true', help='do not print the banner')
    sub = parser.add_subparsers(dest='command', metavar='{scan,diff,runs,doctor}')

    sub.add_parser('doctor', help='show which tools were found and their versions')

    history = argparse.ArgumentParser(add_help=False)
    history.add_argument('target', nargs='?', help='target name as shown by `reconic runs`')
    history.add_argument('-o', '--output-dir', type=Path, default=Path('reconic_output'), metavar='DIR',
                         help='directory holding the history (default ./reconic_output)')
    history.add_argument('--json', action='store_true', help='print JSON instead of text')

    sub.add_parser('runs', parents=[history], help='list recorded runs')
    diff = sub.add_parser(
        'diff', parents=[history], help='show what changed between two runs',
        description='Compares the latest run of a target with the one before it, unless --old/--new say otherwise.')
    diff.add_argument('--old', type=int, metavar='RUN', help='run id to compare from')
    diff.add_argument('--new', type=int, metavar='RUN', help='run id to compare to')

    scan = sub.add_parser(
        'scan', help='run the recon pipeline',
        description='Runs enumerate -> resolve -> probe -> crawl -> takeover -> nuclei, never leaving the scope. '
                    'Ctrl-C stops the run and keeps what it has found.')
    target = scan.add_argument_group('scope')
    target.add_argument('-d', '--domain', action='append', default=[], metavar='DOMAIN',
                        help='domain whose subdomains are in scope and get enumerated (repeatable)')
    target.add_argument('-u', '--host', action='append', default=[], metavar='HOST_OR_URL',
                        help='single host in scope, tested as is with no enumeration (repeatable)')
    target.add_argument('--scope', type=Path, metavar='FILE',
                        help="scope file: one pattern per line, '!' prefix excludes, '#' comments")
    target.add_argument('-x', '--exclude', action='append', default=[], metavar='PATTERN',
                        help='pattern to keep out of scope, e.g. admin.example.com or *.corp.example.com')
    target.add_argument('--program', metavar='h1:HANDLE',
                        help='import the scope of a HackerOne program (needs HACKERONE_API_USERNAME and '
                             'HACKERONE_API_TOKEN) and apply its rules file')
    target.add_argument('--rules', type=Path, metavar='FILE',
                        help='rules of engagement file (default for --program: '
                             '~/.config/reconic/programs/h1-HANDLE.rules)')

    stages = scan.add_argument_group('stages')
    stages.add_argument('--passive', action='store_true',
                        help='enumeration only; nothing is sent to the target')
    stages.add_argument('--no-crawl', action='store_true', help='skip katana')
    stages.add_argument('--no-takeover', action='store_true', help='skip the takeover check')
    stages.add_argument('--no-nuclei', action='store_true', help='skip the nuclei vulnerability scan')
    stages.add_argument('--dns-only', action='store_true',
                        help='enumerate and resolve only; no HTTP request is sent to the target')
    stages.add_argument('--no-resolve', action='store_true',
                        help='skip the DNS check and probe every enumerated host')
    stages.add_argument('--pick', action='store_true',
                        help='choose which alive hosts to continue with after probing')

    net = scan.add_argument_group('network')
    net.add_argument('--proxy', metavar='URL', help='send every tool through this HTTP/SOCKS5 proxy')
    net.add_argument('--tor', action='store_true', help=f"shorthand for --proxy {TOR_PROXY}")
    net.add_argument('--no-firewall', action='store_true',
                     help='do not route httpx, katana and nuclei through the scope firewall')
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
                     help='where run directories and the history are kept (default ./reconic_output)')
    out.add_argument('--notify', action='append', default=[], metavar='WEBHOOK',
                     help='Slack, Discord or generic webhook that receives what is new after the run '
                          '(repeatable; also read from the RECONIC_NOTIFY environment variable)')
    out.add_argument('--name', metavar='NAME',
                     help='name this target is tracked under in the history (default: first scope pattern)')
    out.add_argument('-y', '--yes', action='store_true',
                     help='confirm you are authorized to test this scope, without the prompt')
    return parser


def build_scope(args: argparse.Namespace, program: Optional[dict] = None, rules: Optional[Rules] = None) -> Scope:
    include: List[str] = list(program['include']) if program else []
    exclude: List[str] = list(args.exclude) + (program['exclude'] if program else [])
    if rules:
        exclude += rules.exclude
    for domain in args.domain:
        host = host_of(domain)
        if host is None:
            raise ValueError(f"not a valid domain: {domain!r}")
        include += [host, f"*.{host}"]
    for target in args.host:
        host = host_of(target)
        if host is None:
            raise ValueError(f"not a valid host or URL: {target!r}")
        port = urlsplit(target if '://' in target else '//' + target).port
        include.append(f"{host}:{port}" if port and ':' not in host else host)
    if args.scope:
        file_include, file_exclude = Scope.parse_file(args.scope)
        include += file_include
        exclude += file_exclude
    scope = Scope(include, exclude)
    if not scope.enumeration_roots() and not scope.seeds():
        raise ValueError("nothing to start from: the scope names no host, network or domain to enumerate "
                         f"({', '.join(scope.include)})")
    return scope


def build_options(args: argparse.Namespace, rules: Optional[Rules] = None) -> RunOptions:
    if args.proxy and args.tor:
        raise ValueError("use either --proxy or --tor, not both")
    rules = rules or Rules()
    headers = list(args.header)
    if args.cookie:
        headers.append(f"Cookie: {args.cookie}")
    headers += [header for header in rules.headers if header not in headers]
    for header in headers:
        if ':' not in header or not header.split(':', 1)[0].strip():
            raise ValueError(f'header must look like "Name: value": {header!r}')
    if args.rate_limit is not None and args.rate_limit < 1:
        raise ValueError("--rate-limit must be at least 1")
    proxy = TOR_PROXY if args.tor else args.proxy
    if proxy and not args.no_firewall:
        Upstream(proxy)  # fail now, not mid-scan, on a proxy the firewall cannot chain to
    limits = [limit for limit in (args.rate_limit, rules.rate_limit) if limit]
    return RunOptions(proxy=proxy, headers=headers, rate_limit=min(limits) if limits else None)


def load_rules(args: argparse.Namespace) -> Tuple[Rules, Optional[Path]]:
    """The rules to apply, and the path of a template if one was just written for a program."""
    if args.rules:
        return Rules.load(args.rules), None
    if args.program:
        platform, handle = parse_program(args.program)
        return load_for_program(platform, handle, f"{platform}:{handle}")
    return Rules(), None


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
    noun = {'enumerate': 'host(s)', 'resolve': 'resolving', 'probe': 'alive', 'crawl': 'endpoint(s)'}.get(report.name, 'finding(s)')
    parts = [f"{report.count} {noun}"]
    if report.out_of_scope:
        parts.append(f"{report.out_of_scope} out of scope dropped")
    if report.blocked:
        parts.append(f"{report.blocked} blocked by firewall")
    if report.forbidden:
        parts.append(f"{report.forbidden} forbidden path(s) left out")
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
            elif spec.optional:
                _say(f"  {_paint('–', 'dim')} {spec.name:<10} not found (optional)")
                _say(f"    {' ' * 10} {_paint(spec.install, 'dim')}")
                continue
            else:
                missing += 1
                _say(f"  {_paint('✗', 'red')} {spec.name:<10} not found")
                _say(f"    {' ' * 10} {_paint(spec.install, 'dim')}")
    _say()
    return 1 if missing else 0


def _show_program(program: dict) -> None:
    _say(f"  Program     {program['id']}: {len(program['include'])} in scope, "
         f"{len(program['exclude'])} out of scope · cached as {program['cache']}")
    for note in program['notes']:
        line = f"    {'!' if note['warn'] else '·'} {note['asset']}: {note['note']}"
        _say(_paint(line, 'yellow' if note['warn'] else 'dim'))


def _show_rules(rules: Rules, template: Optional[Path]) -> None:
    if template:
        _say(_paint(f"  Rules       none yet: fill in {template} from the program policy", 'yellow'))
        return
    if rules.empty:
        return
    parts = []
    if rules.rate_limit:
        parts.append(f"{rules.rate_limit} req/s")
    if rules.headers:
        parts.append('header ' + ', '.join(rules.header_names()))
    if rules.forbid:
        parts.append('forbid ' + ' '.join(rules.forbid))
    if rules.hours:
        parts.append('hours ' + rules.describe_hours())
    _say(f"  Rules       {' · '.join(parts) or 'exclusions only'}  {_paint(rules.source or '', 'dim')}")


def _confirm(scope: Scope, config: ScanConfig, yes: bool) -> bool:
    _say("  Scope")
    unseeded = scope.unseeded()
    ports = scope.ports()
    for pattern in scope.include:
        note = _paint("  filter only: names no host or domain to start from", 'yellow') if pattern in unseeded else ''
        if pattern in ports:
            note = _paint(f"  probed on port {', '.join(map(str, ports[pattern]))}", 'dim')
        _say(f"    {_paint('+', 'green')} {pattern}{note}")
    for pattern in scope.exclude:
        _say(f"    {_paint('-', 'red')} {pattern}")
    if not (config.passive or config.dns_only):
        if config.firewall:
            _say("  Firewall    on: httpx, katana and nuclei can only connect to in-scope hosts")
        else:
            _say(_paint("  Firewall    off: nothing stops a tool from connecting out of scope", 'yellow'))
    if config.options.proxy:
        _say(f"  Proxy       every tool, DNS lookups may still be made locally by the tools")
    if config.options.headers:
        _say(f"  Auth        {len(config.options.headers)} header(s) sent to every in-scope host")
    _say()
    if config.passive or config.dns_only or yes:
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
    firewall = results['firewall']
    if firewall['enabled']:
        _say()
        _say(f"  Firewall  {firewall['connections']} connection(s) to {len(firewall['hosts'])} in-scope host(s) · "
             f"{sum(entry['attempts'] for entry in firewall['blocked'])} blocked")
        for entry in firewall['blocked']:
            _say(f"    {_paint('blocked', 'yellow')}  {entry['host']}  "
                 f"{_paint(str(entry['attempts']) + 'x in ' + ', '.join(entry['stages']), 'dim')}")
        for entry in firewall.get('forbidden') or []:
            _say(f"    {_paint('forbidden', 'yellow')}  {entry['url']}  "
                 f"{_paint(str(entry['attempts']) + 'x in ' + ', '.join(entry['stages']), 'dim')}")
        _say(_paint(f"    receipt: {run_dir / RECEIPT_MD}", 'dim'))
    problems = failed_stages(results)
    if problems:
        _say()
        _say(_paint(f"  {len(problems)} stage(s) did not complete; results are partial:", 'red'))
        for name, detail in problems:
            _say(f"    {name}: {detail}")
    _say()
    _say(f"  Results  {run_dir}")
    _say()


def _when(stamp: str) -> str:
    return stamp[:16].replace('T', ' ') + ' UTC'


def _record(results: dict, run_dir: Path, output_dir: Path, webhooks: List[str]) -> None:
    """Save the run to the history, report what is new since the previous one, and notify."""
    target = results['target']
    try:
        with Store(output_dir / DB_NAME) as store:
            run_id = store.record(results, run_dir)
            previous = store.previous_run(target, run_id)
            diff = store.diff(previous, run_id) if previous else None
    except (sqlite3.Error, StoreError) as error:
        _say(_paint(f"  History not updated: {error}", 'red'))
        return
    items, new_endpoints = highlights(diff) if diff else ([], 0)

    if previous is None:
        _say(f"  Run {run_id}: first recorded run for {target}")
    else:
        _say(f"  Run {run_id}: new since run {previous} ({_when(diff['old']['started'])})")
        if diff['scope_changed']:
            _say(_paint("    the scope changed between these runs", 'yellow'))
        for kind in KINDS:
            entry = diff['kinds'][kind]
            if not entry['comparable'] and kind != 'resolved':
                _say(_paint(f"    {_KIND_LABELS[kind]} not compared: {entry['reason']}", 'dim'))
        for kind, item in items:
            _say(f"    {_paint('+', 'green')} {kind:<9} {describe(kind, item)}")
        if new_endpoints:
            _say(f"    {_paint('+', 'green')} {new_endpoints} endpoint(s)")
        if not items and not new_endpoints:
            _say(_paint("    nothing new", 'dim'))
        _say(_paint(f"    full list: reconic diff {target}", 'dim'))

    if not webhooks:
        return
    if previous is None:
        message = first_run_message(target, run_id, results)
    else:
        message = build_message(target, run_id, items, new_endpoints)
    if message is None:
        _say(_paint("  Nothing new, so no notification was sent", 'dim'))
        return
    for url in webhooks:
        host = urlsplit(url).hostname
        try:
            send(url, payload_for(url, message, target, run_id))
            _say(f"  Notified {host}")
        except NotifyError as error:
            _say(_paint(f"  Notification to {host} failed: {error}", 'red'))


def _open_history(args: argparse.Namespace) -> Optional[Store]:
    path = args.output_dir / DB_NAME
    if not path.is_file():
        _say(_paint(f"  error: no history at {path}; run a scan first or point -o at its output directory", 'red'))
        return None
    return Store(path)


def _runs(args: argparse.Namespace) -> int:
    store = _open_history(args)
    if store is None:
        return 2
    with store:
        runs = store.runs(args.target)
    if args.json:
        print(json.dumps(runs, indent=2))
        return 0
    if not runs:
        _say(f"  No runs recorded for {args.target}." if args.target else "  No runs recorded.")
        return 0
    print(f"{'run':>4}  {'started':<20}  {'target':<24} {'hosts':>6} {'alive':>6} {'endpoints':>9} "
          f"{'takeovers':>9} {'vulns':>6}  incomplete")
    for run in runs:
        counts = run['counts']
        incomplete = ', '.join(name for name, stage in run['stages'].items()
                               if stage['status'] in INCOMPLETE)
        print(f"{run['id']:>4}  {_when(run['started']):<20}  {run['target']:<24} {counts['host']:>6} "
              f"{counts['alive']:>6} {counts['endpoint']:>9} {counts['takeover']:>9} {counts['vuln']:>6}  "
              f"{incomplete}")
    return 0


def _diff(args: argparse.Namespace) -> int:
    store = _open_history(args)
    if store is None:
        return 2
    with store:
        try:
            target = args.target
            if args.new is not None:
                run = store.run(args.new)
                if run is None:
                    raise StoreError(f"no such run: {args.new}")
                target = target or run['target']
            if target is None:
                targets = store.targets()
                if len(targets) != 1:
                    raise StoreError("name the target to diff: " + ', '.join(targets))
                target = targets[0]
            runs = store.runs(target)
            if not runs:
                raise StoreError(f"no runs recorded for {target}")
            new_id = args.new if args.new is not None else runs[-1]['id']
            old_id = args.old if args.old is not None else store.previous_run(target, new_id)
            if old_id is None:
                raise StoreError(f"run {new_id} is the first run of {target}; nothing to compare with")
            diff = store.diff(old_id, new_id)
        except StoreError as error:
            _say(_paint(f"  error: {error}", 'red'))
            return 2

    if args.json:
        print(json.dumps(diff, indent=2))
        return 0
    out = sys.stdout
    print(f"{diff['target']}  run {diff['old']['id']} ({_when(diff['old']['started'])}) -> "
          f"run {diff['new']['id']} ({_when(diff['new']['started'])})")
    if diff['scope_changed']:
        print(_paint("note: the scope changed between these runs", 'yellow', out))
    print()
    for kind in KINDS:
        entry = diff['kinds'][kind]
        label = f"{_KIND_LABELS[kind]:<10}"
        if not entry['comparable']:
            print(f"{label} {_paint('not compared: ' + entry['reason'], 'dim', out)}")
        elif not entry['added'] and not entry['removed']:
            print(f"{label} {_paint('no change', 'dim', out)}")
        else:
            print(f"{label} +{len(entry['added'])} -{len(entry['removed'])}")
            for item in entry['added']:
                print(f"  {_paint('+', 'green', out)} {describe(kind, item)}")
            for key in entry['removed']:
                print(f"  {_paint('-', 'red', out)} {key}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return 2
    if args.command in ('runs', 'diff'):
        return _runs(args) if args.command == 'runs' else _diff(args)
    if not args.no_banner:
        print_banner()

    try:
        if args.command == 'doctor':
            return asyncio.run(_doctor())

        try:
            rules, template = load_rules(args)
            program = import_program(args.program) if args.program else None
            scope = build_scope(args, program, rules)
            options = build_options(args, rules)
            webhooks = [check_url(url) for url in
                        args.notify + os.environ.get('RECONIC_NOTIFY', '').replace(',', ' ').split()]
        except (ValueError, OSError, ProgramError) as error:
            _say(_paint(f"  error: {error}", 'red'))
            return 2

        config = ScanConfig(
            scope=scope, name=args.name or (program and program['handle']), output_dir=args.output_dir,
            options=options, rules=rules, program=program,
            passive=args.passive, dns_only=args.dns_only, resolve=not args.no_resolve, crawl=not args.no_crawl, takeover=not args.no_takeover,
            nuclei=not args.no_nuclei, firewall=not args.no_firewall, all_sources=args.all_sources,
            threads=args.threads,
            depth=args.depth, headless=args.headless, crawl_minutes=args.crawl_minutes,
            severity=args.severity, templates=args.templates, stage_timeout=args.stage_timeout * 60,
        )
        if program:
            _show_program(program)
        _show_rules(rules, template)
        active = not (config.passive or config.dns_only)
        problem = rules.window_problem() if active else None
        if problem:
            _say(_paint(f"  error: not starting: {problem}", 'red'))
            return 2
        if not _confirm(scope, config, args.yes):
            _say("  Scan cancelled.")
            return 2

        pipeline = Pipeline(config, on_start=_stage_start, on_end=_stage_end,
                            picker=_pick if args.pick and sys.stdin.isatty() else None)
        try:
            results = asyncio.run(pipeline.run())
        except KeyboardInterrupt:
            results = pipeline.results  # Python before 3.11 raises here even though the run saved itself
            if results is None:
                raise
        _summary(results, pipeline.run_dir)
        _record(results, pipeline.run_dir, args.output_dir, [] if results['interrupted'] else webhooks)
        _say()
        print(pipeline.run_dir / 'results.json')
        if results['interrupted']:
            _say(_paint("  Interrupted; running tools were stopped and the partial results were saved.", 'yellow'))
            return 130
        return 1 if failed_stages(results) else 0
    except KeyboardInterrupt:
        _say(_paint("\n  Interrupted; running tools were stopped.", 'yellow'))
        return 130


if __name__ == '__main__':
    sys.exit(main())
