"""Rules of engagement: how a program lets you test, kept in a small file you edit once.

    rate-limit: 10                       max requests per second, given to every tool
    header: X-HackerOne-Research: you    sent with every request (repeatable)
    forbid: /logout                      path no tool may be pointed at or crawl into (repeatable)
    exclude: blog.example.com            extra out-of-scope pattern (repeatable)
    hours: 22:00-06:00                   scans may only start inside this window
    timezone: Europe/Amsterdam           time zone of hours (default UTC)

A rule can only make a scan gentler or narrower, never wider. Unknown keys are
an error, so a typo cannot silently drop a rule.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone, tzinfo
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import unquote, urlsplit

_HOURS_RE = re.compile(r'^(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})$')
_KEYS = ('rate-limit', 'header', 'forbid', 'exclude', 'hours', 'timezone')

TEMPLATE = """\
# Rules of engagement for {program}
# Copy these from the program policy. Every line is optional, and a rule can only
# make a scan gentler or narrower. Remove the '# ' in front of a line to use it.
#
# rate-limit: 10                          max requests per second, for every tool
# header: X-HackerOne-Research: yourname  sent with every request (repeatable)
# forbid: /logout                         path never handed to or crawled by a tool (repeatable)
# exclude: blog.example.com               extra out-of-scope host or pattern (repeatable)
# hours: 22:00-06:00                      scans may only start inside this window
# timezone: UTC                           time zone of hours, e.g. Europe/Amsterdam
"""


class RulesError(ValueError):
    pass


def config_dir() -> Path:
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(os.path.expanduser('~'), '.config')
    return Path(base) / 'reconic'


def rules_path(platform: str, handle: str) -> Path:
    return config_dir() / 'programs' / f"{platform}-{handle}.rules"


def _zone(name: str) -> tzinfo:
    if name.upper() == 'UTC':
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:  # unknown name, or no time zone database on this system
        raise RulesError(f"unknown time zone: {name!r}") from None


def _path_regex(path: str) -> str:
    """Regex for a forbidden path: '/logout' also covers /logout/, /logout?x and /logout.php."""
    body = ''.join('.*' if ch == '*' else re.escape(ch) for ch in path)
    return body if path.endswith(('/', '*')) else body + r'(?:[/?#;.]|$)'


@dataclass
class Rules:
    source: Optional[str] = None
    rate_limit: Optional[int] = None
    headers: List[str] = field(default_factory=list)
    forbid: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    hours: Optional[Tuple[time, time]] = None
    timezone: str = 'UTC'

    @classmethod
    def parse(cls, text: str, source: Optional[str] = None) -> 'Rules':
        rules = cls(source=source)
        for number, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            key, sep, value = line.partition(':')
            key, value = key.strip().lower(), value.strip()
            where = f"{source or 'rules'}:{number}"
            if not sep or key not in _KEYS:
                raise RulesError(f"{where}: unknown rule {key!r}; known rules are {', '.join(_KEYS)}")
            if not value:
                raise RulesError(f"{where}: {key} needs a value")
            try:
                rules._set(key, value)
            except RulesError as error:
                raise RulesError(f"{where}: {error}") from None
        _zone(rules.timezone)
        return rules

    @classmethod
    def load(cls, path: Path) -> 'Rules':
        return cls.parse(Path(path).read_text(encoding='utf-8'), str(path))

    def _set(self, key: str, value: str) -> None:
        if key == 'rate-limit':
            if not value.isdigit() or int(value) < 1:
                raise RulesError(f"rate-limit must be a whole number of at least 1, not {value!r}")
            self.rate_limit = int(value) if self.rate_limit is None else min(self.rate_limit, int(value))
        elif key == 'header':
            if ':' not in value or not value.split(':', 1)[0].strip():
                raise RulesError(f'header must look like "Name: value": {value!r}')
            self.headers.append(value)
        elif key == 'forbid':
            if not value.startswith('/'):
                raise RulesError(f"forbid takes a path starting with '/', not {value!r}")
            self.forbid.append(value)
        elif key == 'exclude':
            self.exclude.append(value)
        elif key == 'hours':
            match = _HOURS_RE.match(value)
            if not match:
                raise RulesError(f"hours must look like 22:00-06:00, not {value!r}")
            h1, m1, h2, m2 = (int(n) for n in match.groups())
            if h1 > 23 or h2 > 23 or m1 > 59 or m2 > 59 or (h1, m1) == (h2, m2):
                raise RulesError(f"hours is not a usable window: {value!r}")
            self.hours = (time(h1, m1), time(h2, m2))
        else:
            _zone(value)
            self.timezone = value

    @property
    def empty(self) -> bool:
        return not (self.rate_limit or self.headers or self.forbid or self.exclude or self.hours)

    def header_names(self) -> List[str]:
        return [header.split(':', 1)[0].strip() for header in self.headers]

    def forbids(self, target: str) -> bool:
        """True when the path of a URL (or a bare path) is forbidden. Case is ignored, which blocks more."""
        if not self.forbid:
            return False
        path = unquote(urlsplit(target).path) or '/'
        return any(re.match('(?i)^' + _path_regex(rule), path) for rule in self.forbid)

    def url_regexes(self) -> List[str]:
        """Forbidden paths as full-URL regexes, for katana's out-of-scope crawl rules."""
        return [f"(?i)^https?://[^/?#]+{_path_regex(rule)}" for rule in self.forbid]

    def window_problem(self, now: Optional[datetime] = None) -> Optional[str]:
        """Why a scan may not start now, or None when it may."""
        if self.hours is None:
            return None
        start, end = self.hours
        local = (now or datetime.now(timezone.utc)).astimezone(_zone(self.timezone))
        current = local.time().replace(second=0, microsecond=0, tzinfo=None)
        inside = start <= current < end if start < end else (current >= start or current < end)
        if inside:
            return None
        wait = (datetime.combine(local.date(), start) - datetime.combine(local.date(), current)) % timedelta(days=1)
        hours, minutes = divmod(wait.seconds // 60, 60)
        return (f"the program allows scans from {start:%H:%M} to {end:%H:%M} {self.timezone}; it is "
                f"{current:%H:%M} there now, so the window opens in {hours}h{minutes:02d}m")

    def describe_hours(self) -> str:
        return f"{self.hours[0]:%H:%M}-{self.hours[1]:%H:%M} {self.timezone}" if self.hours else ''

    def to_dict(self) -> dict:
        return {'source': self.source, 'rate_limit': self.rate_limit, 'headers': self.header_names(),
                'forbid': list(self.forbid), 'exclude': list(self.exclude),
                'hours': self.describe_hours() or None}


def load_for_program(platform: str, handle: str, program: str) -> Tuple[Rules, Optional[Path]]:
    """The program's rules file, or empty rules and the path of a template written for it."""
    path = rules_path(platform, handle)
    if path.is_file():
        return Rules.load(path), None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(TEMPLATE.format(program=program), encoding='utf-8')
    return Rules(source=str(path)), path
