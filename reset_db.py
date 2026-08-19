"""
reset_db.py: Resets the SQLite incident database and autoincrement sequence counters
so new incidents start cleanly from ID #1.
"""

import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "backend", "sentry.db")


def reset_database():
    if not os.path.exists(DB_PATH):
        print(f"[INFO] Database file not found at {DB_PATH}. Creating fresh database schema...")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Re-initialize schema if needed
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER NOT NULL,
            threat_type TEXT NOT NULL,
            confidence REAL NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            analyst_notes TEXT DEFAULT '',
            correlated INTEGER DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_stats (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        )
    """)

    # Clear incidents and reset AUTOINCREMENT sequence
    cursor.execute("DELETE FROM incidents")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='incidents'")
    cursor.execute("INSERT OR REPLACE INTO system_stats (key, value) VALUES ('total_flows_classified', 0)")

    conn.commit()
    conn.close()
    print("[OK] SQLite database reset successfully! Incident IDs will start at #1.")


if __name__ == "__main__":
    reset_database()
