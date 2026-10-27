"""
CVE Reference & KEV Flags Repository
Provides CRUD operations for CVE reference data and KEV catalog.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from app.core.database import get_db_connection


class CVERepository:

    @staticmethod
    def upsert_many(cves: List[Dict[str, Any]]) -> int:
        """
        Bulk upsert CVE records. Returns count of inserted/updated rows.
        Expected keys per dict: cve_id, description, cvss_score, cvss_vector,
        severity, published_date, last_modified, raw_json, source
        """
        if not cves:
            return 0
        conn, db_type = get_db_connection()
        cursor = conn.cursor()

        now = datetime.now(timezone.utc).isoformat()
        count = 0

        for cve in cves:
            cve_id = cve.get("cve_id")
            if not cve_id:
                continue
            description = cve.get("description", "")
            cvss_score = cve.get("cvss_score")
            cvss_vector = cve.get("cvss_vector", "")
            severity = cve.get("severity", "UNKNOWN")
            published_date = cve.get("published_date")
            last_modified = cve.get("last_modified")
            raw_json = json.dumps(cve.get("raw_json", {}))
            source = cve.get("source", "NVD")

            if db_type == "postgres":
                cursor.execute("""
                    INSERT INTO cve_reference (cve_id, description, cvss_score, cvss_vector, severity, published_date, last_modified, raw_json, source, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        description = EXCLUDED.description,
                        cvss_score = EXCLUDED.cvss_score,
                        cvss_vector = EXCLUDED.cvss_vector,
                        severity = EXCLUDED.severity,
                        published_date = EXCLUDED.published_date,
                        last_modified = EXCLUDED.last_modified,
                        raw_json = EXCLUDED.raw_json,
                        source = EXCLUDED.source
                """, (cve_id, description, cvss_score, cvss_vector, severity, published_date, last_modified, raw_json, source, now))
            else:
                cursor.execute("""
                    INSERT INTO cve_reference (cve_id, description, cvss_score, cvss_vector, severity, published_date, last_modified, raw_json, source, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        description = excluded.description,
                        cvss_score = excluded.cvss_score,
                        cvss_vector = excluded.cvss_vector,
                        severity = excluded.severity,
                        published_date = excluded.published_date,
                        last_modified = excluded.last_modified,
                        raw_json = excluded.raw_json,
                        source = excluded.source
                """, (cve_id, description, cvss_score, cvss_vector, severity, published_date, last_modified, raw_json, source, now))
            count += 1

        conn.commit()
        conn.close()
        return count

    @staticmethod
    def get_by_cve(cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single CVE record by ID."""
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        if db_type == "postgres":
            cursor.execute("SELECT * FROM cve_reference WHERE cve_id = %s", (cve_id.upper(),))
        else:
            cursor.execute("SELECT * FROM cve_reference WHERE cve_id = ?", (cve_id.upper(),))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        res = dict(row)
        if res.get("raw_json"):
            try:
                res["raw_json"] = json.loads(res["raw_json"])
            except Exception:
                pass
        return res

    @staticmethod
    def get_by_cves(cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Fetch multiple CVEs by ID list. Returns dict keyed by CVE ID."""
        if not cve_ids:
            return {}
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        placeholders = ",".join(["%s"] * len(cve_ids)) if db_type == "postgres" else ",".join(["?"] * len(cve_ids))
        upper_ids = [c.upper() for c in cve_ids]
        cursor.execute(f"SELECT * FROM cve_reference WHERE cve_id IN ({placeholders})", upper_ids)
        rows = cursor.fetchall()
        conn.close()
        result = {}
        for row in rows:
            res = dict(row)
            if res.get("raw_json"):
                try:
                    res["raw_json"] = json.loads(res["raw_json"])
                except Exception:
                    pass
            result[res["cve_id"]] = res
        return result

    @staticmethod
    def get_kev_flag(cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch KEV flag for a CVE."""
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        if db_type == "postgres":
            cursor.execute("SELECT * FROM kev_flags WHERE cve_id = %s", (cve_id.upper(),))
        else:
            cursor.execute("SELECT * FROM kev_flags WHERE cve_id = ?", (cve_id.upper(),))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def upsert_kev_many(kev_entries: List[Dict[str, Any]]) -> int:
        """Bulk upsert KEV catalog entries."""
        if not kev_entries:
            return 0
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        count = 0

        for entry in kev_entries:
            cve_id = entry.get("cve_id")
            if not cve_id:
                continue
            added_date = entry.get("added_date")
            vuln_name = entry.get("vuln_name", "")
            short_description = entry.get("short_description", "")
            required_action = entry.get("required_action", "")
            due_date = entry.get("due_date")

            if db_type == "postgres":
                cursor.execute("""
                    INSERT INTO kev_flags (cve_id, added_date, vuln_name, short_description, required_action, due_date, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        added_date = EXCLUDED.added_date,
                        vuln_name = EXCLUDED.vuln_name,
                        short_description = EXCLUDED.short_description,
                        required_action = EXCLUDED.required_action,
                        due_date = EXCLUDED.due_date
                """, (cve_id.upper(), added_date, vuln_name, short_description, required_action, due_date, now))
            else:
                cursor.execute("""
                    INSERT INTO kev_flags (cve_id, added_date, vuln_name, short_description, required_action, due_date, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        added_date = excluded.added_date,
                        vuln_name = excluded.vuln_name,
                        short_description = excluded.short_description,
                        required_action = excluded.required_action,
                        due_date = excluded.due_date
                """, (cve_id.upper(), added_date, vuln_name, short_description, required_action, due_date, now))
            count += 1

        conn.commit()
        conn.close()
        return count

    @staticmethod
    def count_cves() -> int:
        """Return total CVE count in database."""
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM cve_reference")
        row = cursor.fetchone()
        conn.close()
        return row["cnt"] if row else 0

    @staticmethod
    def count_kev() -> int:
        """Return total KEV count in database."""
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM kev_flags")
        row = cursor.fetchone()
        conn.close()
        return row["cnt"] if row else 0