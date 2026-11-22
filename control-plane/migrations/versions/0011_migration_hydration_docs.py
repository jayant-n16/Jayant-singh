"""migration engine: hydration document state (FR-04)

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-21 12:00:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0011'
down_revision: str | Sequence[str] | None = '0010'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('migration_hydration_docs',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('pipeline', sa.String(length=63), nullable=False),
    sa.Column('collection', sa.String(length=128), nullable=False),
    sa.Column('doc_key', sa.String(length=512), nullable=False),
    sa.Column('doc_json', sa.Text(), nullable=False),
    sa.Column('has_root', sa.Boolean(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_migration_hydration_docs_pipeline'), 'migration_hydration_docs', ['pipeline'],
                    unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_migration_hydration_docs_pipeline'), table_name='migration_hydration_docs')
    op.drop_table('migration_hydration_docs')
