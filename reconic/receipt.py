"""receipt.md: one page per run that shows a program what a scan did.

It says which hosts were contacted and how often, everything the firewall
refused, and how each tool was configured: rate limit, required headers and
whether it ran behind the firewall. It is written to be pasted into a report.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import List

from .firewall import RECEIPT_NAME

RECEIPT_MD = 'receipt.md'


def _when(stamp: str) -> str:
    return stamp[:16].replace('T', ' ') + ' UTC'


def _table(header: List[str], rows: List[List[str]]) -> List[str]:
    cell = lambda text: str(text).replace('|', '\\|') or '-'
    lines = ['| ' + ' | '.join(header) + ' |', '|' + '---|' * len(header)]
    return lines + ['| ' + ' | '.join(cell(text) for text in row) + ' |' for row in rows]


def _code(items: List[str]) -> str:
    return ', '.join(f"`{item}`" for item in items)


def _program_lines(program: dict) -> List[str]:
    skipped = [n for n in program['notes'] if n['note'].startswith('skipped')]
    warned = [n for n in program['notes'] if n['warn']]
    line = (f"- **Program:** {program['id']}, scope fetched {_when(program['fetched'])}: "
            f"{len(program['include'])} in-scope and {len(program['exclude'])} out-of-scope pattern(s)")
    if skipped:
        line += f", {len(skipped)} asset(s) not scanned"
    lines = [line]
    for note in warned:
        lines.append(f"  - ⚠ `{note['asset']}`: {note['note']}")
    return lines


def _rules_lines(rules: dict) -> List[str]:
    parts = []
    if rules.get('rate_limit'):
        parts.append(f"at most {rules['rate_limit']} requests/s per tool")
    if rules.get('headers'):
        parts.append(f"required header(s) {_code(rules['headers'])}")
    if rules.get('forbid'):
        parts.append(f"forbidden path(s) {_code(rules['forbid'])}")
    if rules.get('exclude'):
        parts.append(f"extra exclusion(s) {_code(rules['exclude'])}")
    if rules.get('hours'):
        parts.append(f"start window {rules['hours']}")
    if not parts:
        return ['- **Rules of engagement:** none set']
    return [f"- **Rules of engagement:** {'; '.join(parts)}" + (f" (from `{Path(rules['source']).name}`)" if rules.get('source') else '')]


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(65536), b''):
            digest.update(block)
    return digest.hexdigest()


def render(results: dict, run_dir: Path) -> str:
    firewall = results['firewall']
    rules = results.get('rules') or {}
    lines = [f"# Scope receipt: {results['target']}", '',
             f"- **Run:** {_when(results['started'])} to {_when(results['finished'])}, "
             f"Reconic {results['reconic_version']}" + (" (interrupted)" if results['interrupted'] else '')]
    if results.get('program'):
        lines += _program_lines(results['program'])
    lines += _rules_lines(rules)
    scope = results['scope']
    lines.append(f"- **Scope:** {_code(scope['include'])}" +
                 (f"; excluded {_code(scope['exclude'])}" if scope['exclude'] else ''))
    lines.append('')

    if not firewall['enabled']:
        lines += ['## Hosts contacted', '',
                  'The scope firewall was off for this run (or nothing was sent to the target), '
                  'so there is no record of connections.', '']
    else:
        lines += ['## Hosts contacted', '',
                  'Every connection a tool opened went through the scope firewall. HTTPS keeps several '
                  'requests on one connection, so these are connections, not requests.', '']
        contacted = firewall.get('contacted') or []
        lines += _table(['Host', 'Connections', 'Stages'],
                        [[f"`{e['host']}`", e['connections'], ', '.join(e['stages'])] for e in contacted]) \
            if contacted else ['No connections were made.']
        lines += ['', '## Blocked', '']
        blocked = [[f"`{e['host']}`", 'out of scope', e['attempts'], ', '.join(e['stages'])]
                   for e in firewall['blocked']]
        blocked += [[f"`{e['url']}`", 'forbidden path', e['attempts'], ', '.join(e['stages'])]
                    for e in firewall.get('forbidden') or []]
        lines += _table(['Host or URL', 'Reason', 'Attempts', 'Stages'], blocked) if blocked \
            else ['Nothing was blocked: no tool tried to leave the scope.']
        lines.append('')

    invocations = results.get('invocations') or []
    if invocations:
        lines += ['## Tool configuration', '',
                  'subfinder and dnsx ask third-party sources and DNS resolvers, never the target. '
                  'Header values are redacted; the command lines are kept in the run directory.', '']
        lines += _table(['Stage', 'Tool', 'Route', 'Rate limit', 'Headers sent', 'Command line'],
                        [[i['stage'], i['tool'], i['route'], f"{i['rate_limit']}/s" if i['rate_limit'] else 'none',
                          _code(i['headers']) or 'none', f"`{i['cmd']}`"] for i in invocations])
        required = rules.get('headers') or []
        if required:
            missing = [i['tool'] for i in invocations
                       if i['route'].startswith('scope firewall') and not set(required) <= set(i['headers'])]
            lines.append('')
            lines.append(f"Required header(s) {_code(required)} were given to every tool that contacts the target."
                         if not missing else
                         f"⚠ Required header(s) {_code(required)} were NOT given to: {', '.join(missing)}.")
            checks = firewall.get('header_checks') or {}
            if checks.get('checked'):
                seen = checks['checked'] - checks['missing']
                warn = '⚠ ' if checks['missing'] else ''
                lines.append(f"{warn}On the wire, {seen} of {checks['checked']} plain-HTTP request(s) carried them "
                             "(HTTPS requests are encrypted and cannot be checked)." +
                             (" The tools sent the others without them; they are marked `required_headers` "
                              f"in `{RECEIPT_NAME}`." if checks['missing'] else ''))
        lines.append('')

    receipt = Path(run_dir) / RECEIPT_NAME
    if receipt.is_file():
        count = sum(1 for _ in open(receipt, encoding='utf-8'))
        lines += ['---', '',
                  f"Full log: `{RECEIPT_NAME}`, {count} record(s), sha256 `{_digest(receipt)}`", '']
    return '\n'.join(lines)
