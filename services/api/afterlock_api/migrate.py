"""Explicit, ordered, plain-SQL schema migrations.

Migrations live in ``migrations/NNNN_name.sql`` (repository root, or the directory named
by ``AFTERLOCK_MIGRATIONS_DIR``). Versions must be contiguous from 0001. Each migration
runs in its own transaction together with its ``schema_migrations`` row, so a failed
migration leaves no partial record. An applied migration whose file content changed
(checksum mismatch), or an applied version with no file, is refused: history is never
rewritten silently.

The runner works with any DB-API connection. PostgreSQL is the supported target; the
unit tests drive it with ``sqlite3`` using sqlite-compatible fixture migrations.

Usage: ``AFTERLOCK_DATABASE_URL=postgresql://... python -m afterlock_api.migrate [--target N]``
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FILE_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")
LOCK_KEY = 0x0AF7E1_0C  # arbitrary constant for the PostgreSQL advisory lock


class MigrationError(Exception):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str
    checksum: str


def default_dir() -> Path:
    env = os.environ.get("AFTERLOCK_MIGRATIONS_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[3] / "migrations"


def load(directory: Path | None = None) -> list[Migration]:
    d = directory or default_dir()
    if not d.is_dir():
        raise MigrationError(f"migrations directory not found: {d}")
    out: list[Migration] = []
    for path in sorted(d.iterdir()):
        if path.suffix != ".sql":
            continue
        m = FILE_RE.match(path.name)
        if not m:
            raise MigrationError(f"migration file name must be NNNN_name.sql: {path.name}")
        # Normalize line endings so a CRLF checkout does not look like an edited migration.
        sql = path.read_bytes().decode("utf-8").replace("\r\n", "\n")
        out.append(Migration(int(m.group(1)), m.group(2), sql, "sha256:" + hashlib.sha256(sql.encode()).hexdigest()))
    for expected, mig in enumerate(out, start=1):
        if mig.version != expected:
            raise MigrationError(f"migrations must be contiguous from 0001; found {mig.version:04d} where {expected:04d} was expected")
    return out


def _run_script(conn: Any, sql: str) -> None:
    script = getattr(conn, "executescript", None)
    if script is not None:  # sqlite3
        script(sql)
    else:  # psycopg accepts several statements in one execute() when no parameters are bound
        conn.execute(sql)


def applied(conn: Any) -> dict[int, tuple[str, str]]:
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version integer PRIMARY KEY, name text NOT NULL, checksum text NOT NULL, applied_at text NOT NULL)"
    )
    conn.commit()
    cur.execute("SELECT version, name, checksum FROM schema_migrations ORDER BY version")
    rows = cur.fetchall()
    return {int(_col(r, 0, "version")): (str(_col(r, 1, "name")), str(_col(r, 2, "checksum"))) for r in rows}


def _col(row: Any, i: int, key: str) -> Any:
    return row[key] if isinstance(row, dict) else row[i]


def check(migrations: list[Migration], done: dict[int, tuple[str, str]]) -> None:
    known = {m.version: m for m in migrations}
    for version, (name, checksum) in sorted(done.items()):
        m = known.get(version)
        if m is None:
            raise MigrationError(f"database has applied migration {version:04d}_{name} that is not present in this release")
        if m.checksum != checksum:
            raise MigrationError(f"applied migration {version:04d}_{m.name} was edited (checksum {checksum} != {m.checksum}); add a new migration instead")


def apply(
    conn: Any,
    migrations: list[Migration] | None = None,
    *,
    target: int | None = None,
    placeholder: str = "%s",
    lock: Callable[[Any], None] | None = None,
) -> list[int]:
    """Apply pending migrations up to ``target`` (inclusive). Returns the versions applied."""
    migs = load() if migrations is None else migrations
    if lock is not None:
        lock(conn)
    done = applied(conn)
    check(migs, done)
    ran: list[int] = []
    for m in migs:
        if m.version in done:
            continue
        if target is not None and m.version > target:
            break
        try:
            _run_script(conn, m.sql)
            conn.cursor().execute(
                f"INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder})",
                (m.version, m.name, m.checksum, dt.datetime.now(dt.UTC).isoformat()),
            )
            conn.commit()
        except Exception as exc:
            conn.rollback()
            raise MigrationError(f"migration {m.version:04d}_{m.name} failed: {exc}") from exc
        ran.append(m.version)
    return ran


def current_version(conn: Any) -> int:
    done = applied(conn)
    return max(done, default=0)


def postgres_lock(conn: Any) -> None:
    # Session-level advisory lock: concurrent migrators serialize instead of racing.
    conn.execute("SELECT pg_advisory_lock(%s)", (LOCK_KEY,))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="afterlock-migrate", description=__doc__.splitlines()[0])
    ap.add_argument("--target", type=int, default=None)
    ap.add_argument("--status", action="store_true", help="print applied versions and exit")
    args = ap.parse_args(argv)
    url = os.environ.get("AFTERLOCK_DATABASE_URL")
    if not url:
        print("AFTERLOCK_DATABASE_URL is not set", file=sys.stderr)
        return 2
    import psycopg  # optional dependency: pip install 'afterlock[postgres]'

    with psycopg.connect(url) as conn:
        if args.status:
            print(sorted(applied(conn)))
            return 0
        try:
            ran = apply(conn, target=args.target, lock=postgres_lock)
        except MigrationError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    print(f"applied {ran}" if ran else "schema up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
