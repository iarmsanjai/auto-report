import sqlite3
import json
from pathlib import Path
from datetime import datetime

DB_PATH = Path("vapt_reports.db")

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            username TEXT,
            client_name TEXT,
            project_id TEXT,
            updated_at TEXT,
            data TEXT,
            status TEXT DEFAULT 'draft'
        )''')

init_db()

def save_report(report_id: str, username: str, client_name: str, project_id: str, data: dict, status: str = 'draft'):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            INSERT INTO reports (id, username, client_name, project_id, updated_at, data, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                username=excluded.username,
                client_name=excluded.client_name,
                project_id=excluded.project_id,
                updated_at=excluded.updated_at,
                data=excluded.data
        ''', (report_id, username, client_name, project_id, datetime.utcnow().isoformat(), json.dumps(data), status))

def update_report_status(report_id: str, status: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("UPDATE reports SET status=? WHERE id=?", (status, report_id))

def get_reports(admin: bool = False, username: str = None):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if admin:
            cur = conn.execute("SELECT id, username, client_name, project_id, updated_at, status, json_extract(data, '$.meta.scanType') as scanType, json_extract(data, '$.meta.edit_requested_by') as edit_requested_by FROM reports ORDER BY updated_at DESC")
        else:
            cur = conn.execute("SELECT id, username, client_name, project_id, updated_at, status, json_extract(data, '$.meta.scanType') as scanType, json_extract(data, '$.meta.edit_requested_by') as edit_requested_by FROM reports WHERE username=? ORDER BY updated_at DESC", (username,))
        return [dict(row) for row in cur.fetchall()]

def get_report(report_id: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT username, client_name, project_id, data, status FROM reports WHERE id=?", (report_id,))
        row = cur.fetchone()
        if row:
            return {
                "username": row["username"],
                "client_name": row["client_name"],
                "project_id": row["project_id"],
                "data": json.loads(row["data"]),
                "status": row["status"]
            }
        return None

def delete_report(report_id: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM reports WHERE id=?", (report_id,))
