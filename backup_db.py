#!/usr/bin/env python3
"""
ScholarFinder — Database Backup Script
Run daily via PythonAnywhere scheduled tasks:
  python3 /home/scholarfinder/scholar-finder-web/backup_db.py

Keeps last 7 backups, auto-rotates old ones.
"""
import os
import shutil
import sqlite3
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, 'scholarweb.db')
BACKUP_DIR = os.path.join(SCRIPT_DIR, 'backups')
MAX_BACKUPS = 7

def backup():
    if not os.path.exists(DB_PATH):
        print('No database found at', DB_PATH)
        return

    os.makedirs(BACKUP_DIR, exist_ok=True)

    # Use SQLite online backup API for safe copy
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(BACKUP_DIR, f'scholarweb_{timestamp}.db')

    try:
        src = sqlite3.connect(DB_PATH)
        dst = sqlite3.connect(backup_path)
        src.backup(dst)
        dst.close()
        src.close()
        print(f'Backup created: {backup_path}')
    except Exception as e:
        print(f'Backup failed: {e}')
        # Fallback to file copy
        shutil.copy2(DB_PATH, backup_path)
        print(f'Fallback copy created: {backup_path}')

    # Rotate old backups
    backups = sorted([
        f for f in os.listdir(BACKUP_DIR) if f.startswith('scholarweb_') and f.endswith('.db')
    ])
    while len(backups) > MAX_BACKUPS:
        old = backups.pop(0)
        os.remove(os.path.join(BACKUP_DIR, old))
        print(f'Removed old backup: {old}')

    print(f'Total backups: {len(backups)}')

if __name__ == '__main__':
    backup()
