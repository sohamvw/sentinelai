"""
Policy Rules Repository
Provides CRUD operations for policy rules with regulator/sector tagging.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from app.core.database import get_db_connection


class PolicyRulesRepository:

    @staticmethod
    def upsert_many(rules: List[Dict[str, Any]]) -> int:
        """
        Bulk upsert policy rules. Returns count of inserted/updated rows.
        Expected keys per dict: id, regulator, act, section, rule_id, rule_text,
        patterns_json (list), severity, sector_tags_json (list), source, is_canonical
        """
        if not rules:
            return 0
        conn, db_type = get_db_connection()
        cursor = conn.cursor()

        now = datetime.now(timezone.utc).isoformat()
        count = 0

        for rule in rules:
            rule_id = rule.get("id") or f"pol-{uuid.uuid4().hex[:12]}"
            regulator = rule.get("regulator", "UNKNOWN")
            act = rule.get("act", "")
            section = rule.get("section", "")
            rule_code = rule.get("rule_id", "")
            rule_text = rule.get("rule_text", "")
            patterns = json.dumps(rule.get("patterns_json", []))
            severity = rule.get("severity", "MEDIUM")
            sector_tags = json.dumps(rule.get("sector_tags_json", []))
            source = rule.get("source", "canonical")
            # psycopg2 does not coerce SQLite-style 0/1 integers to PostgreSQL
            # BOOLEAN columns. Keep the value native for Postgres and convert it
            # only for the SQLite schema below.
            is_canonical = bool(rule.get("is_canonical", True))
            stored_is_canonical = is_canonical if db_type == "postgres" else int(is_canonical)

            if db_type == "postgres":
                cursor.execute("""
                    INSERT INTO policy_rules (id, regulator, act, section, rule_id, rule_text, patterns_json, severity, sector_tags_json, source, is_canonical, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (act, section, rule_id) DO UPDATE SET
                        regulator = EXCLUDED.regulator,
                        rule_text = EXCLUDED.rule_text,
                        patterns_json = EXCLUDED.patterns_json,
                        severity = EXCLUDED.severity,
                        sector_tags_json = EXCLUDED.sector_tags_json,
                        source = EXCLUDED.source,
                        is_canonical = EXCLUDED.is_canonical
                """, (rule_id, regulator, act, section, rule_code, rule_text, patterns, severity, sector_tags, source, stored_is_canonical, now))
            else:
                cursor.execute("""
                    INSERT INTO policy_rules (id, regulator, act, section, rule_id, rule_text, patterns_json, severity, sector_tags_json, source, is_canonical, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(act, section, rule_id) DO UPDATE SET
                        regulator = excluded.regulator,
                        rule_text = excluded.rule_text,
                        patterns_json = excluded.patterns_json,
                        severity = excluded.severity,
                        sector_tags_json = excluded.sector_tags_json,
                        source = excluded.source,
                        is_canonical = excluded.is_canonical
                """, (rule_id, regulator, act, section, rule_code, rule_text, patterns, severity, sector_tags, source, stored_is_canonical, now))
            count += 1

        conn.commit()
        conn.close()
        return count

    @staticmethod
    def get_by_sector(sector: str) -> List[Dict[str, Any]]:
        """Fetch all rules tagged for a sector (sector_tags_json contains sector)."""
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        # The persisted column is TEXT on both database engines. Cast only for
        # the PostgreSQL containment check rather than assuming a JSONB column.
        if db_type == "postgres":
            cursor.execute(
                "SELECT * FROM policy_rules "
                "WHERE sector_tags_json::jsonb @> %s::jsonb",
                (json.dumps([sector]),),
            )
        else:
            cursor.execute("SELECT * FROM policy_rules WHERE sector_tags_json LIKE ?", (f"%{sector}%",))
        rows = cursor.fetchall()
        conn.close()
        result = []
        for row in rows:
            res = dict(row)
            for jkey in ("patterns_json", "sector_tags_json"):
                if res.get(jkey):
                    try:
                        res[jkey] = json.loads(res[jkey])
                    except Exception:
                        res[jkey] = []
            result.append(res)
        return result

    @staticmethod
    def get_by_regulator(regulator: str) -> List[Dict[str, Any]]:
        """Fetch all rules for a regulator."""
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        if db_type == "postgres":
            cursor.execute("SELECT * FROM policy_rules WHERE regulator = %s", (regulator,))
        else:
            cursor.execute("SELECT * FROM policy_rules WHERE regulator = ?", (regulator,))
        rows = cursor.fetchall()
        conn.close()
        result = []
        for row in rows:
            res = dict(row)
            for jkey in ("patterns_json", "sector_tags_json"):
                if res.get(jkey):
                    try:
                        res[jkey] = json.loads(res[jkey])
                    except Exception:
                        res[jkey] = []
            result.append(res)
        return result

    @staticmethod
    def get_all() -> List[Dict[str, Any]]:
        """Fetch all policy rules."""
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM policy_rules")
        rows = cursor.fetchall()
        conn.close()
        result = []
        for row in rows:
            res = dict(row)
            for jkey in ("patterns_json", "sector_tags_json"):
                if res.get(jkey):
                    try:
                        res[jkey] = json.loads(res[jkey])
                    except Exception:
                        res[jkey] = []
            result.append(res)
        return result

    @staticmethod
    def count() -> int:
        """Return total policy rule count."""
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM policy_rules")
        row = cursor.fetchone()
        conn.close()
        return row["cnt"] if row else 0
