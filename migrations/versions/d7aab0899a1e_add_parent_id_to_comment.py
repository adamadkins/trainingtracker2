"""Add parent_id to Comment

Revision ID: d7aab0899a1e
Revises: 446021581352
Create Date: 2025-01-07 13:16:54.298261

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd7aab0899a1e'
down_revision = '446021581352'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.add_column(sa.Column('parent_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            'fk_comment_parent_id',  # Name of the foreign key constraint
            'comment',  # Referencing table
            ['parent_id'],  # Column in the current table
            ['id'],  # Referenced column in the referenced table
        )

    # ### end Alembic commands ###


def downgrade():
    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.drop_constraint('fk_comment_parent_id', type_='foreignkey')  # Drop the named foreign key
        batch_op.drop_column('parent_id')

    # ### end Alembic commands ###
