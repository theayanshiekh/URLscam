"""
db.py
-----
Lightweight SQLite repository for audit logging of URL scans and managing
user/analyst feedback reports (false positives & false negatives for active retraining).
"""

import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional


class Database:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        self.is_memory = (self.db_path == ":memory:")
        self._memory_conn = None
        
        if not self.is_memory:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        else:
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row

        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        if self.is_memory:
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_connection()
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    is_flagged INTEGER NOT NULL,
                    probability REAL NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    ip_address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feedback_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    reported_as TEXT NOT NULL,
                    actual_status TEXT NOT NULL,
                    notes TEXT,
                    submitted_by TEXT DEFAULT 'anonymous',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_logs_created ON scan_logs (created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback_reports (created_at)")
            conn.commit()

    def log_scan(
        self,
        url: str,
        is_flagged: bool,
        probability: float,
        risk_score: float,
        risk_level: str,
        ip_address: Optional[str] = None,
    ):
        conn = self.get_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO scan_logs (url, is_flagged, probability, risk_score, risk_level, ip_address)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (url, int(is_flagged), probability, risk_score, risk_level, ip_address),
            )
            conn.commit()

    def add_report(
        self,
        url: str,
        reported_as: str,
        actual_status: str,
        notes: str = "",
        submitted_by: str = "anonymous",
    ) -> int:
        conn = self.get_connection()
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO feedback_reports (url, reported_as, actual_status, notes, submitted_by)
                VALUES (?, ?, ?, ?, ?)
                """,
                (url, reported_as, actual_status, notes, submitted_by),
            )
            conn.commit()
            return cursor.lastrowid

    def get_recent_reports(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, url, reported_as, actual_status, notes, submitted_by, created_at
                FROM feedback_reports
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_scan_stats(self) -> Dict[str, Any]:
        conn = self.get_connection()
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total_scans, SUM(is_flagged) as total_flagged FROM scan_logs")
            row = cursor.fetchone()
            total_scans = row["total_scans"] or 0
            total_flagged = row["total_flagged"] or 0

            cursor.execute("SELECT COUNT(*) as total_reports FROM feedback_reports")
            total_reports = cursor.fetchone()["total_reports"] or 0

            return {
                "total_scans": total_scans,
                "total_flagged": total_flagged,
                "total_clean": total_scans - total_flagged,
                "total_feedback_reports": total_reports,
            }
