"""SQLite cache for NVD responses, keyed by the queried virtualMatchString."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

DEFAULT_TTL = 7 * 24 * 3600

# The table name carries the payload version: entries cached before a parser
# change would be missing fields, so the old table goes rather than being read.
_SCHEMA = """
DROP TABLE IF EXISTS cve_cache;
CREATE TABLE IF NOT EXISTS cve_cache_v2 (
    key        TEXT PRIMARY KEY,
    fetched_at INTEGER NOT NULL,
    payload    TEXT NOT NULL
)
"""


class Cache:
    def __init__(self, path: Path, ttl: int = DEFAULT_TTL, enabled: bool = True):
        self.path = path
        self.ttl = ttl
        self.enabled = enabled
        self._conn: sqlite3.Connection | None = None
        if enabled:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(path)
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def get(self, key: str):
        if not self._conn:
            return None
        row = self._conn.execute(
            "SELECT fetched_at, payload FROM cve_cache_v2 WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        fetched_at, payload = row
        if time.time() - fetched_at > self.ttl:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None

    def put(self, key: str, value) -> None:
        if not self._conn:
            return
        self._conn.execute(
            "INSERT OR REPLACE INTO cve_cache_v2 (key, fetched_at, payload) VALUES (?, ?, ?)",
            (key, int(time.time()), json.dumps(value, ensure_ascii=False)),
        )
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Cache":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
