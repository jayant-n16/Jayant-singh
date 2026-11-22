"""dr jobs (restore drills and other long-running DR jobs)

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-21 00:00:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0010'
down_revision: str | Sequence[str] | None = '0009'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('dr_jobs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('target', sa.String(length=512), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('step', sa.String(length=32), nullable=False),
    sa.Column('payload_json', sa.Text(), nullable=False),
    sa.Column('state_json', sa.Text(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('requested_by', sa.String(length=256), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_dr_jobs_created_at'), 'dr_jobs', ['created_at'], unique=False)
    op.create_index(op.f('ix_dr_jobs_kind'), 'dr_jobs', ['kind'], unique=False)
    op.create_index(op.f('ix_dr_jobs_status'), 'dr_jobs', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_dr_jobs_status'), table_name='dr_jobs')
    op.drop_index(op.f('ix_dr_jobs_kind'), table_name='dr_jobs')
    op.drop_index(op.f('ix_dr_jobs_created_at'), table_name='dr_jobs')
    op.drop_table('dr_jobs')
