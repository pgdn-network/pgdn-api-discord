#!/usr/bin/env python3
"""
Test script to check actual enum values in the database.
"""

import os
import sys
import logging
from sqlalchemy import create_engine, text

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_enum_values():
    """Test what enum values are actually in the database."""

    # Get database URL
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        logger.error("DATABASE_URL not set")
        return

    try:
        # Create engine
        engine = create_engine(database_url)

        with engine.connect() as conn:
            # Check what enum values exist in the database
            logger.info("Checking actual enum values in database...")

            result = conn.execute(text("""
                SELECT DISTINCT simple_state
                FROM nodes
                WHERE simple_state IS NOT NULL
                LIMIT 10
            """))

            rows = result.fetchall()
            if rows:
                logger.info(f"Found {len(rows)} distinct simple_state values:")
                for row in rows:
                    value = row[0]
                    logger.info(f"  simple_state = '{value}' (type: {type(value).__name__})")
            else:
                logger.info("No simple_state values found in nodes table")

            # Also check the PostgreSQL enum type definition
            logger.info("\nChecking PostgreSQL enum type definition...")
            result = conn.execute(text("""
                SELECT enumlabel
                FROM pg_enum
                WHERE enumtypid = (
                    SELECT oid
                    FROM pg_type
                    WHERE typname = 'simplenodestate'
                )
                ORDER BY enumsortorder
            """))

            enum_rows = result.fetchall()
            if enum_rows:
                logger.info("PostgreSQL enum 'simplenodestate' possible values:")
                for row in enum_rows:
                    value = row[0]
                    logger.info(f"  '{value}'")
            else:
                logger.info("No enum type 'simplenodestate' found")

    except Exception as e:
        logger.error(f"Error testing enum values: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_enum_values()