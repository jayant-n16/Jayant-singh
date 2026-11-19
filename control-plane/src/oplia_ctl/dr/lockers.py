"""Force DR target databases into read-only mode (and back), per engine.

Every ``lock()`` changes the target, then **verifies** the change on a fresh connection and
returns exactly what it did, so ``unlock(state)`` reverses only that.

* PostgreSQL - ``ALTER SUBSCRIPTION ... DISABLE`` (stops applying incoming changes),
  ``ALTER DATABASE ... SET default_transaction_read_only = on`` and terminates the other client
  sessions of that database so they reconnect read-only. Note: a superuser can still override
  with ``SET``; give applications non-superuser roles.
* MySQL 8 - ``STOP REPLICA`` (if it is a replica) and ``SET PERSIST super_read_only = ON``
  (blocks writes for every account including SUPER, and survives a restart).
* MongoDB - ``fsync`` with ``lock: true`` on the DR member: writes block until ``fsyncUnlock``.
* CockroachDB - ``ALTER ROLE ALL IN DATABASE ... SET default_transaction_read_only = 'on'``.
  Existing sessions keep their mode until they reconnect (not cancelled automatically).

For PostgreSQL and CockroachDB the DSN must connect to the target database itself; this is
checked with ``current_database()`` before anything is changed.

Credentials (DSNs / URIs) are secrets resolved at call time; they never appear in results.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from oplia_ctl.secrets import SecretProvider

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$-]{0,62}$")


def _text(value: Any) -> str:
    """psycopg returns bytes for text columns of SQL_ASCII databases."""
    return value.decode("utf-8", "replace") if isinstance(value, (bytes, bytearray, memoryview)) else str(value)


def _ident(name: str) -> str:
    if not _IDENT.fullmatch(name):
        raise ValueError(f"invalid identifier {name!r}")
    return '"' + name.replace('"', '""') + '"'


class TargetSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    engine: Literal["postgres", "mysql", "mongodb", "cockroachdb"]
    cloud: Literal["aws", "azure", "gcp", "ibm", "onprem"]
    dsn_secret: str = Field(min_length=1, max_length=128)  # secret holding the DSN / URI
    database: str | None = None                           # postgres / cockroachdb


class TargetLocker(Protocol):
    name: str

    def lock(self) -> dict[str, Any]: ...

    def unlock(self, state: dict[str, Any]) -> dict[str, Any]: ...


class PostgresLocker:
    def __init__(self, spec: TargetSpec, secrets: SecretProvider,
                 connect: Callable[[str], Any] | None = None) -> None:
        if not spec.database:
            raise ValueError(f"target {spec.name}: database is required for postgres")
        _ident(spec.database)
        self.name = spec.name
        self._db = spec.database
        self._dsn: Callable[[], str] = lambda: secrets.get(spec.dsn_secret)
        self._connect = connect or self._psycopg

    @staticmethod
    def _psycopg(dsn: str) -> Any:
        import psycopg

        return psycopg.connect(dsn, autocommit=True, connect_timeout=10)

    def _setting(self) -> str:
        with self._connect(self._dsn()) as c:
            return _text(c.execute("SHOW default_transaction_read_only").fetchone()[0])

    def _check_db(self, c: Any) -> None:
        current = _text(c.execute("SELECT current_database()").fetchone()[0])
        if current != self._db:
            raise ValueError(f"{self.name}: DSN connects to database {current!r}, expected {self._db!r}")

    def lock(self) -> dict[str, Any]:
        db = _ident(self._db)
        with self._connect(self._dsn()) as c:
            self._check_db(c)
            subs = [_text(r[0]) for r in c.execute(
                "SELECT subname FROM pg_subscription s JOIN pg_database d ON d.oid = s.subdbid "
                "WHERE d.datname = %s AND s.subenabled", (self._db,)).fetchall()]
            for sub in subs:
                c.execute(f"ALTER SUBSCRIPTION {_ident(sub)} DISABLE")
            c.execute(f"ALTER DATABASE {db} SET default_transaction_read_only = on")
            killed = c.execute(
                "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = %s "
                "AND pid <> pg_backend_pid() AND backend_type = 'client backend'", (self._db,)).fetchone()[0]
        verified = self._setting()
        if verified != "on":
            raise RuntimeError(f"{self.name}: default_transaction_read_only is {verified!r} after lock")
        return {"engine": "postgres", "database": self._db, "disabled_subscriptions": subs,
                "terminated_sessions": int(killed), "verified_read_only": True}

    def unlock(self, state: dict[str, Any]) -> dict[str, Any]:
        db = _ident(self._db)
        with self._connect(self._dsn()) as c:
            # this session started read-only because of the lock itself: lift it for this session first
            c.execute("SET SESSION default_transaction_read_only = off")
            c.execute(f"ALTER DATABASE {db} RESET default_transaction_read_only")
            for sub in state.get("disabled_subscriptions") or []:
                c.execute(f"ALTER SUBSCRIPTION {_ident(sub)} ENABLE")
        return {"engine": "postgres", "database": self._db, "read_only": self._setting(),
                "enabled_subscriptions": state.get("disabled_subscriptions") or []}


class MySQLLocker:
    def __init__(self, spec: TargetSpec, secrets: SecretProvider,
                 connect: Callable[[str], Any] | None = None) -> None:
        self.name = spec.name
        self._dsn: Callable[[], str] = lambda: secrets.get(spec.dsn_secret)
        self._connect = connect or self._pymysql

    @staticmethod
    def _pymysql(dsn: str) -> Any:
        """DSN: mysql://user:password@host:port/?ssl_ca=/path (ssl_ca optional)."""
        from urllib.parse import parse_qs, unquote, urlsplit

        import pymysql

        u = urlsplit(dsn)
        if u.scheme != "mysql" or not u.hostname:
            raise ValueError("MySQL DSN must be mysql://user:password@host:port/")
        q = parse_qs(u.query)
        ssl = {"ca": q["ssl_ca"][0]} if "ssl_ca" in q else None
        return pymysql.connect(host=u.hostname, port=u.port or 3306, user=unquote(u.username or ""),
                               password=unquote(u.password or ""), connect_timeout=10, autocommit=True, ssl=ssl)

    @staticmethod
    def _q(conn: Any, sql: str) -> list[tuple[Any, ...]]:
        with conn.cursor() as cur:
            cur.execute(sql)
            return list(cur.fetchall())

    def _read_only(self) -> int:
        conn = self._connect(self._dsn())
        try:
            return int(self._q(conn, "SELECT @@GLOBAL.super_read_only")[0][0])
        finally:
            conn.close()

    def lock(self) -> dict[str, Any]:
        conn = self._connect(self._dsn())
        try:
            replica = bool(self._q(conn, "SHOW REPLICA STATUS"))
            if replica:
                self._q(conn, "STOP REPLICA")
            self._q(conn, "SET PERSIST super_read_only = ON")
        finally:
            conn.close()
        if self._read_only() != 1:
            raise RuntimeError(f"{self.name}: super_read_only is not ON after lock")
        return {"engine": "mysql", "stopped_replica": replica, "verified_read_only": True}

    def unlock(self, state: dict[str, Any]) -> dict[str, Any]:
        conn = self._connect(self._dsn())
        try:
            self._q(conn, "SET PERSIST super_read_only = OFF")
            self._q(conn, "SET PERSIST read_only = OFF")
            if state.get("stopped_replica"):
                self._q(conn, "START REPLICA")
        finally:
            conn.close()
        return {"engine": "mysql", "super_read_only": self._read_only(),
                "started_replica": bool(state.get("stopped_replica"))}


class MongoLocker:
    def __init__(self, spec: TargetSpec, secrets: SecretProvider,
                 client_factory: Callable[[str], Any] | None = None) -> None:
        self.name = spec.name
        self._uri: Callable[[], str] = lambda: secrets.get(spec.dsn_secret)
        self._factory = client_factory or self._pymongo

    @staticmethod
    def _pymongo(uri: str) -> Any:
        from pymongo import MongoClient

        return MongoClient(uri, serverSelectionTimeoutMS=10000, directConnection=True)

    def lock(self) -> dict[str, Any]:
        client = self._factory(self._uri())
        try:
            res = client.admin.command("fsync", lock=True)
            if int(res.get("lockCount", 0)) < 1:
                raise RuntimeError(f"{self.name}: fsync lock not confirmed: {res}")
            return {"engine": "mongodb", "lock_count": int(res["lockCount"]), "verified_read_only": True}
        finally:
            client.close()

    def unlock(self, state: dict[str, Any]) -> dict[str, Any]:
        client = self._factory(self._uri())
        try:
            remaining = 1
            for _ in range(max(1, int(state.get("lock_count", 1)))):
                remaining = int(client.admin.command("fsyncUnlock").get("lockCount", 0))
                if remaining == 0:
                    break
            return {"engine": "mongodb", "lock_count": remaining}
        finally:
            client.close()


class CockroachLocker(PostgresLocker):
    """CockroachDB speaks the PostgreSQL wire protocol; read-only is set per role in the database."""

    def lock(self) -> dict[str, Any]:
        db = _ident(self._db)
        with self._connect(self._dsn()) as c:
            self._check_db(c)
            c.execute(f"ALTER ROLE ALL IN DATABASE {db} SET default_transaction_read_only = 'on'")
        verified = self._setting()
        if verified not in ("on", "true"):
            raise RuntimeError(f"{self.name}: default_transaction_read_only is {verified!r} after lock")
        return {"engine": "cockroachdb", "database": self._db, "verified_read_only": True}

    def unlock(self, state: dict[str, Any]) -> dict[str, Any]:
        db = _ident(self._db)
        with self._connect(self._dsn()) as c:
            c.execute("SET SESSION default_transaction_read_only = off")  # the lock applies to this session too
            c.execute(f"ALTER ROLE ALL IN DATABASE {db} RESET default_transaction_read_only")
        return {"engine": "cockroachdb", "database": self._db, "read_only": "reset"}


def build_locker(spec: TargetSpec, secrets: SecretProvider) -> TargetLocker:
    if spec.engine == "postgres":
        return PostgresLocker(spec, secrets)
    if spec.engine == "mysql":
        return MySQLLocker(spec, secrets)
    if spec.engine == "mongodb":
        return MongoLocker(spec, secrets)
    return CockroachLocker(spec, secrets)
