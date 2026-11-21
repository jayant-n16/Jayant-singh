"""integration settings applied from the console (non-secret values only)

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-21 19:00:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0012'
down_revision: str | Sequence[str] | None = '0011'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('integration_settings',
    sa.Column('env_key', sa.String(length=128), nullable=False),
    sa.Column('value', sa.Text(), nullable=False),
    sa.Column('integration', sa.String(length=64), nullable=False),
    sa.Column('change_id', sa.String(length=36), nullable=False),
    sa.Column('requested_by', sa.String(length=256), nullable=False),
    sa.Column('applied_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('env_key')
    )
    op.create_index(op.f('ix_integration_settings_integration'), 'integration_settings', ['integration'],
                    unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_integration_settings_integration'), table_name='integration_settings')
    op.drop_table('integration_settings')
