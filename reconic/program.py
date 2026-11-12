"""Program import: build a scope from a bug bounty program's own asset list.

HackerOne only for now. Its structured scopes are typed, but the identifiers
are typed by hand: one entry can hold several hosts, a URL with a path, a note
in brackets or a range of addresses. Each entry becomes scope patterns or is
skipped with a note saying why. Whatever cannot be read exactly is skipped
rather than guessed at, so an import never widens the scope beyond what the
program lists.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import quote

from . import __version__
from .scope import _PATTERN_RE

H1_API = 'https://api.hackerone.com/v1'
H1_USERNAME_ENV = 'HACKERONE_API_USERNAME'
H1_TOKEN_ENV = 'HACKERONE_API_TOKEN'
CACHE_NAME = 'program_scope.json'
# Asset types whose identifiers name hosts, URLs or networks. Everything else
# (app store IDs, source code, hardware, executables...) is not for this tool.
WEB_TYPES = ('URL', 'WILDCARD', 'DOMAIN', 'API', 'CIDR', 'IP_ADDRESS', 'IP_RANGE')
_HANDLE_RE = re.compile(r'^[A-Za-z0-9_.-]+$')
_URL_RE = re.compile(r'^(?:[a-z][a-z0-9+.-]*://)?([^/?#]+)(.*)$')
_OPEN_PATHS = ('', '/', '/*', '*')
_PAGE_SIZE = 100
_MAX_PAGES = 50


class ProgramError(Exception):
    pass


def parse_program(text: str) -> Tuple[str, str]:
    """'h1:handle' -> ('h1', 'handle')."""
    platform, sep, handle = text.strip().partition(':')
    if not sep or platform.lower() not in ('h1', 'hackerone'):
        raise ValueError(f"--program must look like h1:<handle> (only HackerOne is supported for now), not {text!r}")
    if not _HANDLE_RE.match(handle):
        raise ValueError(f"not a valid program handle: {handle!r}")
    return 'h1', handle


def _fixed_domain(host: str) -> bool:
    """False for patterns that pin down nothing but a TLD, such as '*.com'."""
    labels = host.split('.')
    if any(not label for label in labels):
        return False
    fixed = [index for index, label in enumerate(labels) if '*' not in label]
    return len(fixed) >= 2 or (len(fixed) == 1 and fixed[0] != len(labels) - 1)


def _token_patterns(token: str) -> Tuple[List[str], str]:
    """Scope patterns for one host, URL, network or address range, and why it was narrowed or refused.

    Returns ([], reason) when the token cannot be used as it is.
    """
    first, dash, last = token.partition('-')
    if dash:
        try:
            low, high = ipaddress.ip_address(first), ipaddress.ip_address(last)
            return [str(n) for n in ipaddress.summarize_address_range(low, high)], ''
        except (ValueError, TypeError):
            pass
    try:
        return [str(ipaddress.ip_network(token, strict=False))], ''
    except ValueError:
        pass
    match = _URL_RE.match(token.lower())
    if not match:
        return [], 'not a host, URL or network'
    host, path = match.group(1), match.group(2)
    host = host.rsplit('@', 1)[-1]
    port = re.search(r':(\d+)$', host)
    host = re.sub(r':(\d+|\*)$', '', host).rstrip('.')
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    try:
        return [str(ipaddress.ip_address(host))], _path_note(path)
    except ValueError:
        pass
    note = _path_note(path)
    if host.startswith('*') and not host.startswith('*.'):
        # '*example.com' would also match 'attacker-example.com'; keep what it surely means
        host = host.lstrip('*')
        found = [host, f"*.{host}"]
        note = note or f"read as {host} and *.{host}"
    else:
        found = [f"{host}:{port.group(1)}" if port and '*' not in host else host]
    if '.' not in host or not _PATTERN_RE.match(host) or not _fixed_domain(host):
        return [], 'not a host, URL or network'
    return found, note


def _path_note(path: str) -> str:
    path = path.split('?', 1)[0].split('#', 1)[0]
    return '' if path in _OPEN_PATHS else f"path:{path}"


def _tokens(identifier: str) -> List[str]:
    text = re.sub(r'\([^)]*\)', ' ', identifier)  # notes in brackets: 'example.com (main site)'
    return [token for token in re.split(r'[\s,;|]+', text) if token]


def read_assets(assets: List[dict]) -> dict:
    """Turn structured scopes into include/exclude patterns plus a note for everything skipped or changed."""
    include, exclude, notes = [], [], []

    def note(asset: dict, text: str, warn: bool = False) -> None:
        notes.append({'asset': asset.get('asset_identifier') or '', 'type': asset.get('asset_type') or '',
                      'in_scope': bool(asset.get('eligible_for_submission')), 'note': text, 'warn': warn})

    for asset in assets:
        identifier = (asset.get('asset_identifier') or '').strip()
        kind = (asset.get('asset_type') or '').upper()
        in_scope = bool(asset.get('eligible_for_submission'))
        if kind not in WEB_TYPES:
            if in_scope:
                note(asset, f"skipped: not a web asset ({kind or 'no type'})")
            continue
        found, reasons = [], []
        for token in _tokens(identifier):
            patterns, reason = _token_patterns(token)
            if not patterns:
                found = []
                reasons = [f"could not read {token!r}"]
                break
            found += patterns
            if reason:
                reasons.append(reason)
        if not found:
            why = reasons[0] if reasons else 'empty identifier'
            if in_scope:
                note(asset, f"skipped: {why}; add what is meant with -u, -d or --scope")
            else:
                note(asset, f"{why}; NOT excluded, add it with -x or an exclude: rule", warn=True)
            continue
        paths = [r[5:] for r in reasons if r.startswith('path:')]
        other = [r for r in reasons if not r.startswith('path:')]
        if paths and in_scope:
            # Reconic scopes whole hosts: taking the host would test more than the program allows
            note(asset, f"skipped: only {', '.join(paths)} is in scope and Reconic tests whole hosts; "
                        "add the host with -u if the program allows the rest of it")
            continue
        if paths:
            note(asset, f"only {', '.join(paths)} is out of scope; the whole host is kept out")
        for text in other:
            note(asset, text)
        target = include if in_scope else exclude
        target += [p for p in found if p not in target]
    return {'include': include, 'exclude': exclude, 'notes': notes}


def h1_credentials() -> Tuple[str, str]:
    username, token = os.environ.get(H1_USERNAME_ENV, ''), os.environ.get(H1_TOKEN_ENV, '')
    if not (username and token):
        raise ProgramError(f"set {H1_USERNAME_ENV} and {H1_TOKEN_ENV} to your HackerOne API identifier and token "
                           "(create them at https://hackerone.com/settings/api_token/edit)")
    return username, token


def _get(url: str, auth: str, timeout: float) -> dict:
    request = urllib.request.Request(url, headers={
        'Authorization': f"Basic {auth}", 'Accept': 'application/json', 'User-Agent': f"reconic/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as error:
        reasons = {401: 'HackerOne rejected the API credentials', 403: 'HackerOne rejected the API credentials',
                   404: 'no such program, or your API token cannot see it',
                   429: 'HackerOne rate limit reached; try again in a minute'}
        raise ProgramError(reasons.get(error.code, f"HackerOne answered HTTP {error.code}")) from None
    except (urllib.error.URLError, OSError) as error:
        raise ProgramError(f"HackerOne unreachable: {getattr(error, 'reason', error)}") from None
    except ValueError:
        raise ProgramError("HackerOne sent something that is not JSON") from None
    if not isinstance(body, dict) or not isinstance(body.get('data'), list):
        raise ProgramError("HackerOne's answer has no list of scopes")
    return body


def fetch_h1(handle: str, username: str, token: str, api: str = H1_API, timeout: float = 30) -> List[dict]:
    """Every structured scope of a program, in-scope and out-of-scope, as the API's attribute dicts."""
    auth = base64.b64encode(f"{username}:{token}".encode('utf-8')).decode('ascii')
    assets = []
    for page in range(1, _MAX_PAGES + 1):
        url = (f"{api}/hackers/programs/{quote(handle, safe='')}/structured_scopes"
               f"?page%5Bnumber%5D={page}&page%5Bsize%5D={_PAGE_SIZE}")
        body = _get(url, auth, timeout)
        assets += [item.get('attributes') or {} for item in body['data'] if isinstance(item, dict)]
        if not body['data'] or not (body.get('links') or {}).get('next'):
            break
    return assets


def import_program(text: str, api: Optional[str] = None) -> dict:
    """Fetch and read a program's scope. The result is what gets cached in the run directory."""
    platform, handle = parse_program(text)
    assets = fetch_h1(handle, *h1_credentials(), api=api or H1_API)
    program = {'platform': 'hackerone', 'handle': handle, 'id': f"{platform}:{handle}",
               'fetched': datetime.now(timezone.utc).isoformat(timespec='seconds'),
               'cache': CACHE_NAME, **read_assets(assets), 'assets': assets}
    if not program['include']:
        raise ProgramError(f"{program['id']} lists no web asset Reconic can scan "
                           f"({len(assets)} asset(s), {len(program['notes'])} skipped)")
    return program


def summary(program: Optional[dict]) -> Optional[dict]:
    """What results.json keeps of an import; the raw assets stay in the cache file."""
    if program is None:
        return None
    return {key: value for key, value in program.items() if key != 'assets'}
