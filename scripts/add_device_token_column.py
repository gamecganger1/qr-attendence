#!/usr/bin/env python3
import sqlite3
import os
import sys

# locate the project's attendance.db (one level up from scripts/)
here = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.normpath(os.path.join(here, '..', 'attendance.db'))

if not os.path.exists(db_path):
    print(f"Database file not found at {db_path}")
    sys.exit(1)

print(f"Using database: {db_path}")
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# check if column exists
cur.execute("PRAGMA table_info('student')")
cols = [row[1] for row in cur.fetchall()]
if 'device_token' in cols:
    print('Column device_token already exists on student table. No action taken.')
    conn.close()
    sys.exit(0)

# add column
try:
    cur.execute("ALTER TABLE student ADD COLUMN device_token VARCHAR(200);")
    conn.commit()
    print('Added column device_token to student table successfully.')
except Exception as e:
    print('Failed to add column:', e)
    conn.rollback()
    conn.close()
    sys.exit(2)

conn.close()
print('Done.')
