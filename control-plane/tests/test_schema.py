"""Guard: the migrations must create every table the models define (PostgreSQL run only).

Added after a migration was generated empty because a models module was not imported in
migrations/env.py - `alembic check` cannot detect that, this test can.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import inspect

from oplia_ctl.db import Base


@pytest.mark.skipif(not os.environ.get("OPLIA_TEST_DATABASE_URL"), reason="schema comes from migrations on PostgreSQL")
def test_migrations_create_every_model_table(session_factory):
    with session_factory() as s:
        created = set(inspect(s.get_bind()).get_table_names())
    assert set(Base.metadata.tables) <= created, sorted(set(Base.metadata.tables) - created)


def test_migration_env_imports_every_models_module():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    env = (root / "migrations" / "env.py").read_text()
    modules = sorted(p.relative_to(root / "src").with_suffix("").as_posix().replace("/", ".")
                     for p in (root / "src" / "oplia_ctl").rglob("models.py"))
    missing = [m for m in modules if f"import {m}" not in env]
    assert not missing, f"migrations/env.py does not import {missing}"
