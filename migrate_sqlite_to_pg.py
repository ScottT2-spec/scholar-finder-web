#!/usr/bin/env python3
"""
Migrate data from SQLite (scholarweb.db) to PostgreSQL.

Usage:
    DATABASE_URL='postgresql://user:pass@host:port/db' python migrate_sqlite_to_pg.py [path_to_scholarweb.db]

This script:
1. Reads all data from the SQLite database
2. Creates tables in PostgreSQL (if they don't exist)
3. Inserts all rows, skipping duplicates
"""
import os
import sys
import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor

DATABASE_URL = os.environ.get('DATABASE_URL', '')
SQLITE_PATH = sys.argv[1] if len(sys.argv) > 1 else 'scholarweb.db'

if not DATABASE_URL:
    print("ERROR: Set DATABASE_URL environment variable")
    print("Example: DATABASE_URL='postgresql://user:pass@host:5432/dbname' python migrate_sqlite_to_pg.py")
    sys.exit(1)

if not os.path.exists(SQLITE_PATH):
    print(f"ERROR: SQLite database not found at {SQLITE_PATH}")
    sys.exit(1)

print(f"Source: {SQLITE_PATH}")
print(f"Target: {DATABASE_URL[:50]}...")

# Connect to both databases
sq = sqlite3.connect(SQLITE_PATH)
sq.row_factory = sqlite3.Row
pg = psycopg2.connect(DATABASE_URL)
cur = pg.cursor()

# Create tables in PostgreSQL
print("\n--- Creating tables ---")
cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        full_name TEXT DEFAULT '',
        country TEXT DEFAULT '',
        field_of_study TEXT DEFAULT '',
        education_level TEXT DEFAULT '',
        gpa TEXT DEFAULT '',
        interests TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        is_admin INTEGER DEFAULT 0,
        email_verified INTEGER DEFAULT 0,
        verification_code TEXT DEFAULT '',
        verification_expires TIMESTAMP DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS bookmarks (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        item_type TEXT NOT NULL,
        item_name TEXT NOT NULL,
        item_data TEXT DEFAULT '{}',
        notes TEXT DEFAULT '',
        status TEXT DEFAULT 'interested',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, item_type, item_name)
    );

    CREATE TABLE IF NOT EXISTS activity_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT DEFAULT '',
        ip_address TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS search_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        query TEXT NOT NULL,
        results_count INTEGER DEFAULT 0,
        category TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS rate_limits (
        id SERIAL PRIMARY KEY,
        key TEXT NOT NULL,
        category TEXT NOT NULL,
        timestamp REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_rate_key_cat ON rate_limits(key, category);

    CREATE TABLE IF NOT EXISTS scholarship_updates (
        id SERIAL PRIMARY KEY,
        action TEXT NOT NULL,
        scholarship_name TEXT NOT NULL,
        data TEXT DEFAULT '{}',
        source TEXT DEFAULT 'webhook',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS link_health (
        id SERIAL PRIMARY KEY,
        scholarship_name TEXT NOT NULL,
        url TEXT NOT NULL,
        status TEXT DEFAULT 'unknown',
        last_checked TIMESTAMP,
        fail_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(scholarship_name)
    );
""")
pg.commit()
print("Tables created.")

# Migrate each table
def migrate_table(table_name, columns):
    """Migrate a table from SQLite to PostgreSQL."""
    try:
        rows = sq.execute(f"SELECT * FROM {table_name}").fetchall()
    except sqlite3.OperationalError:
        print(f"  {table_name}: table not found in SQLite, skipping")
        return 0

    if not rows:
        print(f"  {table_name}: empty, skipping")
        return 0

    # Get column names from the first row
    col_names = [k for k in rows[0].keys() if k in columns]
    placeholders = ', '.join(['%s'] * len(col_names))
    col_str = ', '.join(col_names)

    inserted = 0
    skipped = 0
    for row in rows:
        values = tuple(row[c] for c in col_names)
        try:
            cur.execute(f"INSERT INTO {table_name} ({col_str}) VALUES ({placeholders})", values)
            inserted += 1
        except psycopg2.IntegrityError:
            pg.rollback()
            skipped += 1
            continue
    
    pg.commit()
    
    # Reset the serial sequence to max id
    try:
        cur.execute(f"SELECT MAX(id) FROM {table_name}")
        max_id = cur.fetchone()[0]
        if max_id:
            cur.execute(f"SELECT setval(pg_get_serial_sequence('{table_name}', 'id'), %s)", (max_id,))
            pg.commit()
    except Exception:
        pg.rollback()

    print(f"  {table_name}: {inserted} inserted, {skipped} skipped (duplicates)")
    return inserted

print("\n--- Migrating data ---")
migrate_table('users', ['id', 'email', 'username', 'password_hash', 'salt', 'full_name', 'country', 'field_of_study', 'education_level', 'gpa', 'interests', 'bio', 'is_admin', 'email_verified', 'verification_code', 'verification_expires', 'created_at', 'last_login'])
migrate_table('bookmarks', ['id', 'user_id', 'item_type', 'item_name', 'item_data', 'notes', 'status', 'created_at'])
migrate_table('activity_log', ['id', 'user_id', 'action', 'details', 'ip_address', 'created_at'])
migrate_table('search_log', ['id', 'user_id', 'query', 'results_count', 'category', 'created_at'])
migrate_table('rate_limits', ['id', 'key', 'category', 'timestamp'])
migrate_table('scholarship_updates', ['id', 'action', 'scholarship_name', 'data', 'source', 'created_at'])
migrate_table('link_health', ['id', 'scholarship_name', 'url', 'status', 'last_checked', 'fail_count', 'created_at'])

# Check for sent_emails table
try:
    migrate_table('sent_emails', ['id', 'to_email', 'subject', 'body', 'sent_at'])
except Exception:
    pass

print("\n--- Migration complete! ---")

# Summary
cur.execute("SELECT COUNT(*) FROM users")
print(f"Users in PostgreSQL: {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM bookmarks")
print(f"Bookmarks in PostgreSQL: {cur.fetchone()[0]}")

sq.close()
cur.close()
pg.close()
