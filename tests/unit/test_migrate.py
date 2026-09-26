"""Migration runner tests. Driven by sqlite3 (stdlib) so they run without PostgreSQL."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from afterlock_api import migrate
from afterlock_api.migrate import MigrationError

from conftest import ROOT


def write(d: Path, name: str, sql: str) -> None:
    (d / name).write_bytes(sql.encode())


@pytest.fixture
def mdir(tmp_path: Path) -> Path:
    write(tmp_path, "0001_initial.sql", "CREATE TABLE a (x integer);\n")
    write(tmp_path, "0002_more.sql", "CREATE TABLE b (y integer);\nCREATE INDEX b_y ON b (y);\n")
    return tmp_path


def conn() -> sqlite3.Connection:
    return sqlite3.connect(":memory:")


def tables(c: sqlite3.Connection) -> set[str]:
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def test_repository_migrations_are_ordered_and_named() -> None:
    migs = migrate.load(ROOT / "migrations")
    assert [m.version for m in migs] == list(range(1, len(migs) + 1))
    assert migs[0].name == "initial"
    for m in migs:
        assert m.checksum.startswith("sha256:")
    initial = migs[0].sql
    for table in ("cases", "analysis_manifests", "jobs", "results"):
        assert f"CREATE TABLE {table}" in initial
    assert "job_id          text UNIQUE" in initial  # idempotent publication
    assert initial.count("cluster_id") >= 8


def test_apply_upgrade_and_idempotence(mdir: Path) -> None:
    c = conn()
    migs = migrate.load(mdir)
    assert migrate.apply(c, migs, target=1, placeholder="?") == [1]
    assert "a" in tables(c) and "b" not in tables(c)
    assert migrate.apply(c, migs, placeholder="?") == [2]
    assert {"a", "b", "schema_migrations"} <= tables(c)
    assert migrate.apply(c, migs, placeholder="?") == []
    assert migrate.current_version(c) == 2


def test_edited_applied_migration_is_refused(mdir: Path) -> None:
    c = conn()
    migrate.apply(c, migrate.load(mdir), placeholder="?")
    write(mdir, "0001_initial.sql", "CREATE TABLE a (x integer, z text);\n")
    with pytest.raises(MigrationError, match="edited"):
        migrate.apply(c, migrate.load(mdir), placeholder="?")


def test_crlf_checkout_is_not_an_edit(mdir: Path) -> None:
    c = conn()
    migrate.apply(c, migrate.load(mdir), placeholder="?")
    write(mdir, "0002_more.sql", "CREATE TABLE b (y integer);\r\nCREATE INDEX b_y ON b (y);\r\n")
    assert migrate.apply(c, migrate.load(mdir), placeholder="?") == []


def test_applied_migration_missing_from_release_is_refused(mdir: Path) -> None:
    c = conn()
    migrate.apply(c, migrate.load(mdir), placeholder="?")
    (mdir / "0002_more.sql").unlink()
    with pytest.raises(MigrationError, match="not present"):
        migrate.apply(c, migrate.load(mdir), placeholder="?")


def test_gaps_and_bad_names_are_rejected(tmp_path: Path) -> None:
    write(tmp_path, "0001_a.sql", "SELECT 1;")
    write(tmp_path, "0003_c.sql", "SELECT 1;")
    with pytest.raises(MigrationError, match="contiguous"):
        migrate.load(tmp_path)
    (tmp_path / "0003_c.sql").unlink()
    write(tmp_path, "2_bad.sql", "SELECT 1;")
    with pytest.raises(MigrationError, match="NNNN_name"):
        migrate.load(tmp_path)


def test_failed_migration_is_not_recorded(mdir: Path) -> None:
    write(mdir, "0003_broken.sql", "CREATE TABLE c (;\n")
    c = conn()
    with pytest.raises(MigrationError, match="0003_broken"):
        migrate.apply(c, migrate.load(mdir), placeholder="?")
    assert sorted(migrate.applied(c)) == [1, 2]


def test_cli_requires_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AFTERLOCK_DATABASE_URL", raising=False)
    assert migrate.main([]) == 2
