"""SQLite history of every run, and the diff between two runs.

Each run records which assets it saw. An asset kind maps to the one stage
that produces it, so a diff can refuse to compare a kind whose stage did not
complete in both runs instead of reporting everything as gone.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

DB_NAME = 'reconic.db'
KIND_STAGE = {'host': 'enumerate', 'alive': 'probe', 'endpoint': 'crawl', 'takeover': 'takeover', 'vuln': 'nuclei'}
KINDS = tuple(KIND_STAGE)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id       INTEGER PRIMARY KEY,
    target   TEXT NOT NULL,
    started  TEXT NOT NULL,
    finished TEXT NOT NULL,
    version  TEXT NOT NULL,
    run_dir  TEXT NOT NULL,
    scope    TEXT NOT NULL,
    stages   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
    id        INTEGER PRIMARY KEY,
    target    TEXT NOT NULL,
    kind      TEXT NOT NULL,
    key       TEXT NOT NULL,
    data      TEXT NOT NULL,
    first_run INTEGER NOT NULL REFERENCES runs(id),
    last_run  INTEGER NOT NULL REFERENCES runs(id),
    UNIQUE (target, kind, key)
);
CREATE TABLE IF NOT EXISTS run_assets (
    run_id   INTEGER NOT NULL REFERENCES runs(id),
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    PRIMARY KEY (run_id, asset_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS runs_by_target ON runs (target, id);
"""


class StoreError(Exception):
    pass


def assets_of(results: dict) -> Iterable[Tuple[str, str, dict]]:
    """(kind, key, data) for everything a run found."""
    for host in results['subdomains']:
        yield 'host', host, {}
    for entry in results['alive']:
        yield 'alive', entry['url'], {'status': entry.get('status'), 'title': entry.get('title', '')}
    for url in results['endpoints']:
        yield 'endpoint', url, {}
    for finding in results['findings']:
        kind = 'takeover' if finding.get('stage') == 'takeover' else 'vuln'
        yield kind, f"{finding['template']} {finding['matched']}", {
            'severity': finding.get('severity', ''), 'name': finding.get('name', '')}


def _stage_complete(stages: Dict[str, dict], stage: str) -> Tuple[bool, str]:
    info = stages.get(stage)
    if info is None:
        return False, 'did not run'
    if info['status'] == 'ok':
        return True, ''
    if stage == 'enumerate' and info['status'] == 'skipped' and 'no wildcard' in info['detail']:
        return True, ''  # a scope of fixed hosts needs no enumeration
    if info['status'] == 'skipped':
        return False, f"was skipped ({info['detail']})"
    return False, 'failed' if info['status'] == 'failed' else 'timed out'


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA)

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> 'Store':
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- writing ----------------------------------------------------------

    def record(self, results: dict, run_dir: Path) -> int:
        """Save one finished run and return its id."""
        target = results['target']
        with self.db:
            run_id = self.db.execute(
                "INSERT INTO runs (target, started, finished, version, run_dir, scope, stages) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (target, results['started'], results['finished'], results['reconic_version'], str(run_dir),
                 json.dumps(results['scope'], sort_keys=True), json.dumps(results['stages'])),
            ).lastrowid
            rows = {(kind, key): data for kind, key, data in assets_of(results)}
            self.db.executemany(
                "INSERT INTO assets (target, kind, key, data, first_run, last_run) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (target, kind, key) DO UPDATE SET last_run = excluded.last_run, data = excluded.data",
                [(target, kind, key, json.dumps(data), run_id, run_id) for (kind, key), data in rows.items()],
            )
            self.db.executemany(
                "INSERT INTO run_assets (run_id, asset_id) "
                "SELECT ?, id FROM assets WHERE target = ? AND kind = ? AND key = ?",
                [(run_id, target, kind, key) for kind, key in rows],
            )
        return run_id

    # -- reading ----------------------------------------------------------

    def targets(self) -> List[str]:
        return [row[0] for row in self.db.execute("SELECT DISTINCT target FROM runs ORDER BY target")]

    def run(self, run_id: int) -> Optional[dict]:
        row = self.db.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        run = dict(row)
        run['scope'] = json.loads(run['scope'])
        run['stages'] = {stage['name']: stage for stage in json.loads(run['stages'])}
        return run

    def runs(self, target: Optional[str] = None) -> List[dict]:
        """Runs, oldest first, each with its asset count per kind."""
        query, params = "SELECT id FROM runs", ()
        if target is not None:
            query, params = query + " WHERE target = ?", (target,)
        runs = []
        for (run_id,) in self.db.execute(query + " ORDER BY id", params).fetchall():
            run = self.run(run_id)
            run['counts'] = {kind: 0 for kind in KINDS}
            for kind, count in self.db.execute(
                    "SELECT a.kind, COUNT(*) FROM run_assets ra JOIN assets a ON a.id = ra.asset_id "
                    "WHERE ra.run_id = ? GROUP BY a.kind", (run_id,)):
                run['counts'][kind] = count
            runs.append(run)
        return runs

    def previous_run(self, target: str, before: int) -> Optional[int]:
        row = self.db.execute(
            "SELECT MAX(id) FROM runs WHERE target = ? AND id < ?", (target, before)).fetchone()
        return row[0]

    def _only_in(self, kind: str, present: int, absent: int) -> List[sqlite3.Row]:
        return self.db.execute(
            "SELECT a.key, a.data, a.first_run FROM run_assets ra JOIN assets a ON a.id = ra.asset_id "
            "WHERE ra.run_id = ? AND a.kind = ? AND a.id NOT IN "
            "(SELECT asset_id FROM run_assets WHERE run_id = ?) ORDER BY a.key",
            (present, kind, absent)).fetchall()

    def diff(self, old_id: int, new_id: int) -> dict:
        """What run `new_id` has that `old_id` lacks, and the reverse, per asset kind."""
        old, new = self.run(old_id), self.run(new_id)
        if old is None or new is None:
            raise StoreError(f"no such run: {old_id if old is None else new_id}")
        if old['target'] != new['target']:
            raise StoreError(f"runs {old_id} and {new_id} belong to different targets "
                             f"({old['target']} and {new['target']})")
        kinds = {}
        for kind, stage in KIND_STAGE.items():
            entry = {'comparable': True, 'reason': '', 'added': [], 'removed': []}
            for run in (old, new):
                complete, why = _stage_complete(run['stages'], stage)
                if not complete:
                    entry['comparable'] = False
                    entry['reason'] = f"{stage} {why} in run {run['id']}"
                    break
            if entry['comparable']:
                entry['added'] = [
                    {'key': row['key'], 'seen_before': row['first_run'] < new_id, **json.loads(row['data'])}
                    for row in self._only_in(kind, new_id, old_id)]
                entry['removed'] = [row['key'] for row in self._only_in(kind, old_id, new_id)]
            kinds[kind] = entry
        return {
            'target': new['target'],
            'old': {'id': old['id'], 'started': old['started']},
            'new': {'id': new['id'], 'started': new['started']},
            'scope_changed': old['scope'] != new['scope'],
            'kinds': kinds,
        }
