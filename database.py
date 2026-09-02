import os
import json
import sqlite3

from datetime import datetime


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DATABASE_PATH = os.path.join(
    BASE_DIR,
    "voiceshield.db"
)


def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            caller_name TEXT,
            caller_number TEXT,
            analysis_mode TEXT,
            transcript TEXT,
            risk_score REAL,
            risk_level TEXT,
            detection_result TEXT,
            why_flagged TEXT,
            recommendation TEXT,
            report_path TEXT,
            qr_code_path TEXT
        )
        """
    )

    connection.commit()
    connection.close()


def save_incident_report(
    report,
    report_path="",
    qr_code_path=""
):
    caller_information = report.get(
        "caller_information",
        {}
    )

    why_flagged = report.get(
        "why_flagged",
        []
    )

    connection = get_connection()

    connection.execute(
        """
        INSERT OR REPLACE INTO incident_reports (
            report_id,
            created_at,
            caller_name,
            caller_number,
            analysis_mode,
            transcript,
            risk_score,
            risk_level,
            detection_result,
            why_flagged,
            recommendation,
            report_path,
            qr_code_path
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            report.get("report_id"),
            report.get(
                "date_time",
                datetime.now().strftime(
                    "%d-%m-%Y %I:%M:%S %p"
                )
            ),
            caller_information.get(
                "caller_name",
                "Unknown"
            ),
            caller_information.get(
                "caller_number",
                "Not available"
            ),
            report.get(
                "analysis_mode",
                "Audio Upload"
            ),
            report.get(
                "transcript",
                ""
            ),
            report.get(
                "risk_score",
                0
            ),
            report.get(
                "risk_level",
                "UNKNOWN"
            ),
            report.get(
                "detection_result",
                "Unknown"
            ),
            json.dumps(
                why_flagged,
                ensure_ascii=False
            ),
            report.get(
                "recommendation",
                ""
            ),
            report_path,
            qr_code_path
        )
    )

    connection.commit()
    connection.close()


def get_incident_report(report_id):
    connection = get_connection()

    row = connection.execute(
        """
        SELECT *
        FROM incident_reports
        WHERE report_id = ?
        """,
        (report_id,)
    ).fetchone()

    connection.close()

    if row is None:
        return None

    result = dict(row)

    try:
        result["why_flagged"] = json.loads(
            result.get("why_flagged") or "[]"
        )
    except Exception:
        result["why_flagged"] = []

    return result


def get_all_incident_reports():
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT *
        FROM incident_reports
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    results = []

    for row in rows:
        item = dict(row)

        try:
            item["why_flagged"] = json.loads(
                item.get("why_flagged") or "[]"
            )
        except Exception:
            item["why_flagged"] = []

        results.append(item)

    return results