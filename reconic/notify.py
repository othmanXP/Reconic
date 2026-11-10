"""Webhook notifications for what a run found that the previous run did not."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from . import __version__

MAX_LENGTH = 1800  # Discord rejects messages over 2000 characters


class NotifyError(Exception):
    pass


def describe(kind: str, item: dict) -> str:
    """One line for a newly seen asset."""
    text = item['key']
    if kind in ('takeover', 'vuln'):
        text = f"[{item.get('severity') or 'unknown'}] {text}"
    elif kind == 'alive' and item.get('status'):
        text = f"{text}  [{item['status']}]"
    elif kind == 'resolved' and item.get('address'):
        text = f"{text}  {item['address']}"
    return text + ("  (seen before)" if item.get('seen_before') else "")


def _fit(title: str, lines: List[str], target: str) -> str:
    text, shown = title, 0
    for line in lines:
        if len(text) + len(line) + 1 > MAX_LENGTH:
            break
        text += '\n' + line
        shown += 1
    if shown < len(lines):
        text += f"\n... and {len(lines) - shown} more: reconic diff {target}"
    return text


def build_message(target: str, run_id: int, items: List[Tuple[str, dict]], new_endpoints: int) -> Optional[str]:
    """What is new since the previous run, or None when nothing is."""
    if not items and not new_endpoints:
        return None
    lines = [f"+ {kind} {describe(kind, item)}" for kind, item in items]
    if new_endpoints:
        lines.append(f"+ {new_endpoints} endpoint(s)")
    return _fit(f"Reconic: {target} run {run_id}, {len(items) + new_endpoints} new", lines, target)


def first_run_message(target: str, run_id: int, results: dict) -> str:
    """A first run has no baseline, so send totals and the findings rather than every host."""
    title = (f"Reconic: {target} run {run_id}, first run: {len(results['subdomains'])} host(s), "
             f"{len(results['alive'])} alive, {len(results['endpoints'])} endpoint(s), "
             f"{len(results['findings'])} finding(s)")
    lines = [f"+ {'takeover' if f.get('stage') == 'takeover' else 'vuln'} "
             f"[{f.get('severity') or 'unknown'}] {f['template']} {f['matched']}" for f in results['findings']]
    return _fit(title, lines, target)


def payload_for(url: str, text: str, target: str, run_id: int) -> dict:
    host = (urlsplit(url).hostname or '').lower()
    if host in ('discord.com', 'discordapp.com') or host.endswith('.discord.com'):
        return {'content': text}
    if host == 'hooks.slack.com':
        return {'text': text}
    return {'text': text, 'target': target, 'run': run_id}


def check_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ValueError(f"notification URL must be http(s): {url!r}")
    return url


def send(url: str, payload: dict, timeout: float = 15) -> None:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode('utf-8'), method='POST',
        headers={'Content-Type': 'application/json', 'User-Agent': f"reconic/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout):
            pass
    except urllib.error.HTTPError as error:
        raise NotifyError(f"webhook answered HTTP {error.code}") from None
    except (urllib.error.URLError, OSError) as error:
        raise NotifyError(f"webhook unreachable: {getattr(error, 'reason', error)}") from None
