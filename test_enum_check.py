#!/usr/bin/env python3
"""
Test to check actual enum values in the database.
This will tell us what case the values are actually stored as.
"""

import pytest
import asyncio
from app.models.database import get_db_session
from sqlalchemy import text

def test_check_actual_enum_values():
    """Test what enum values are actually stored in the database."""

    with get_db_session() as session:
        # Check what values are actually in the database
        result = session.execute(text("""
            SELECT DISTINCT simple_state
            FROM nodes
            WHERE simple_state IS NOT NULL
            LIMIT 5
        """))

        db_values = []
        for row in result.fetchall():
            value = row[0]
            db_values.append(value)
            print(f"Database has simple_state = '{value}' (type: {type(value)})")

        # Check the PostgreSQL enum type definition
        result = session.execute(text("""
            SELECT enumlabel
            FROM pg_enum
            WHERE enumtypid = (
                SELECT oid
                FROM pg_type
                WHERE typname = 'simplenodestate'
            )
            ORDER BY enumsortorder
        """))

        pg_enum_values = []
        for row in result.fetchall():
            value = row[0]
            pg_enum_values.append(value)
            print(f"PostgreSQL enum allows: '{value}'")

        print(f"\nSummary:")
        print(f"Database values: {db_values}")
        print(f"PostgreSQL enum allows: {pg_enum_values}")

        # The test passes if we can see the values
        assert len(db_values) > 0 or len(pg_enum_values) > 0, "Should find some enum values"

        return db_values, pg_enum_values

if __name__ == "__main__":
    test_check_actual_enum_values()