import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import bcrypt

from app.core.config import settings

# Postgres driver is loaded lazily so import errors are reported as database
# configuration problems instead of preventing non-DB tooling from importing.
def _try_postgres(database_url: str):
    if not database_url or not database_url.startswith("postgresql"):
        return None
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor, connect_timeout=2)
        return conn, "postgres"
    except Exception as e:
        raise RuntimeError(
            "PostgreSQL is configured but unavailable. Check DATABASE_URL, the "
            "PostgreSQL service, and the psycopg2-binary dependency."
        ) from e


def get_db_connection():
    """
    Return the configured application database connection.

    SentinelAI's real scan/auth/audit state is PostgreSQL-backed. A missing
    DATABASE_URL should fail loudly instead of creating backend/sentinel.db and
    splitting state between two engines.
    """
    database_url = settings.DATABASE_URL
    pg = _try_postgres(database_url)
    if pg is not None:
        return pg

    raise RuntimeError(
        "DATABASE_URL must be set to a PostgreSQL connection string "
        "(for example postgresql://user:password@localhost:5432/sentinelai)."
    )


def get_database_status() -> Dict[str, Any]:
    """Return the actual active database engine and a lightweight query result."""
    try:
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        conn.close()
        return {"configured": True, "connected": True, "engine": db_type}
    except Exception as error:
        return {"configured": bool(settings.DATABASE_URL), "connected": False, "detail": str(error)}


def init_db():
    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    
    if db_type == "postgres":
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(64) PRIMARY KEY,
                first_name VARCHAR(100) NOT NULL,
                last_name VARCHAR(100) NOT NULL,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255),
                auth_provider VARCHAR(50) DEFAULT 'email',
                is_verified BOOLEAN DEFAULT FALSE,
                verification_code VARCHAR(10),
                code_expires_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                username TEXT UNIQUE,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                auth_provider TEXT DEFAULT 'email',
                is_verified INTEGER DEFAULT 0,
                verification_code TEXT,
                code_expires_at TEXT,
                created_at TEXT NOT NULL
            );
        """)
        conn.commit()

    # support_tickets table — both backends.
    if db_type == "postgres":
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS support_tickets (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64),
                user_name VARCHAR(255),
                user_email VARCHAR(255) NOT NULL,
                subject VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                status VARCHAR(32) DEFAULT 'open',
                created_at VARCHAR(64) NOT NULL
            );
        """)
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS support_tickets (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                user_name TEXT,
                user_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                created_at TEXT NOT NULL
            );
        """)
    conn.commit()

    # Dynamic migration check for missing columns on existing SQLite databases.
    if db_type == "sqlite":
        cursor.execute("PRAGMA table_info(users)")
        columns = [row["name"] if isinstance(row, dict) or hasattr(row, "keys") else row[1] for row in cursor.fetchall()]
        if "username" not in columns:
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN username TEXT")
                conn.commit()
            except Exception:
                pass
        if "code_expires_at" not in columns:
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN code_expires_at TEXT")
                conn.commit()
            except Exception:
                pass
        if "auth_provider" not in columns:
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'email'")
                conn.commit()
            except Exception:
                pass

    # --- CVE Reference table ---
    if db_type == "postgres":
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_reference (
                cve_id VARCHAR(32) PRIMARY KEY,
                description TEXT,
                cvss_score NUMERIC(3,1),
                cvss_vector VARCHAR(128),
                severity VARCHAR(16),
                published_date TIMESTAMP WITH TIME ZONE,
                last_modified TIMESTAMP WITH TIME ZONE,
                raw_json JSONB,
                source VARCHAR(16) DEFAULT 'NVD',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_reference_severity ON cve_reference(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_reference_cvss ON cve_reference(cvss_score)")
        conn.commit()
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_reference (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                severity TEXT,
                published_date TEXT,
                last_modified TEXT,
                raw_json TEXT,
                source TEXT DEFAULT 'NVD',
                created_at TEXT NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_reference_severity ON cve_reference(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_reference_cvss ON cve_reference(cvss_score)")
        conn.commit()

    # --- KEV Flags table ---
    if db_type == "postgres":
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS kev_flags (
                cve_id VARCHAR(32) PRIMARY KEY REFERENCES cve_reference(cve_id) ON DELETE CASCADE,
                added_date TIMESTAMP WITH TIME ZONE,
                vuln_name TEXT,
                short_description TEXT,
                required_action TEXT,
                due_date TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS kev_flags (
                cve_id TEXT PRIMARY KEY,
                added_date TEXT,
                vuln_name TEXT,
                short_description TEXT,
                required_action TEXT,
                due_date TEXT,
                created_at TEXT NOT NULL
            );
        """)
        conn.commit()

    # --- Policy Rules table ---
    if db_type == "postgres":
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policy_rules (
                id VARCHAR(64) PRIMARY KEY,
                regulator VARCHAR(64) NOT NULL,
                act VARCHAR(128) NOT NULL,
                section VARCHAR(64) NOT NULL,
                rule_id VARCHAR(64) NOT NULL,
                rule_text TEXT NOT NULL,
                patterns_json TEXT,
                severity VARCHAR(16) NOT NULL,
                sector_tags_json TEXT,
                source VARCHAR(32) DEFAULT 'canonical',
                is_canonical BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_rules_regulator ON policy_rules(regulator)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_rules_sector ON policy_rules(sector_tags_json)")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_rules_act_section_rule ON policy_rules(act, section, rule_id)")
        conn.commit()
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policy_rules (
                id TEXT PRIMARY KEY,
                regulator TEXT NOT NULL,
                act TEXT NOT NULL,
                section TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_text TEXT NOT NULL,
                patterns_json TEXT,
                severity TEXT NOT NULL,
                sector_tags_json TEXT,
                source TEXT DEFAULT 'canonical',
                is_canonical INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_rules_regulator ON policy_rules(regulator)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_rules_sector ON policy_rules(sector_tags_json)")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_rules_act_section_rule ON policy_rules(act, section, rule_id)")
        conn.commit()

    # --- Scans table for real-time tracking ---
    if db_type == "postgres":
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id VARCHAR(64) PRIMARY KEY,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                status VARCHAR(32) DEFAULT 'pending',
                progress_percentage INTEGER DEFAULT 0,
                realtime_status VARCHAR(32) DEFAULT 'active',
                phase_1_completed BOOLEAN DEFAULT FALSE,
                phase_5_completed BOOLEAN DEFAULT FALSE,
                phase_6_completed BOOLEAN DEFAULT FALSE,
                last_updated TIMESTAMP WITH TIME ZONE NOT NULL,
                workspace_path TEXT,
                user_id VARCHAR(64),
                repository_info JSONB
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_realtime_status ON scans(realtime_status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)")
        conn.commit()
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                progress_percentage INTEGER DEFAULT 0,
                realtime_status TEXT DEFAULT 'active',
                phase_1_completed INTEGER DEFAULT 0,
                phase_5_completed INTEGER DEFAULT 0,
                phase_6_completed INTEGER DEFAULT 0,
                last_updated TEXT NOT NULL,
                workspace_path TEXT,
                user_id TEXT,
                repository_info TEXT
            );
        """)
        conn.commit()

    # --- Scan Events table for real-time event tracking ---
    if db_type == "postgres":
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_events (
                id VARCHAR(64) PRIMARY KEY,
                event_type VARCHAR(64) NOT NULL,
                scan_id VARCHAR(64),
                data JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_scan_id ON scan_events(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_event_type ON scan_events(event_type)")
        conn.commit()
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                scan_id TEXT,
                data TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)
        conn.commit()

    # Migrate existing tables to support JSON columns (for backward compatibility)
    if db_type == "sqlite":
        # Add JSON column if not exists (SQLite doesn't support native JSON type)
        try:
            cursor.execute("ALTER TABLE cve_reference ADD COLUMN raw_json TEXT")
            conn.commit()
        except:
            pass

        try:
            cursor.execute("ALTER TABLE kev_flags ADD COLUMN description TEXT")
            conn.commit()
        except:
            pass

        try:
            cursor.execute("ALTER TABLE policy_rules ADD COLUMN sector_tags_json TEXT")
            conn.commit()
        except:
            pass

        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN repository_info TEXT")
            conn.commit()
        except:
            pass

        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN phase_1_completed INTEGER DEFAULT 0")
            conn.commit()
        except:
            pass

        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN phase_5_completed INTEGER DEFAULT 0")
            conn.commit()
        except:
            pass

        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN phase_6_completed INTEGER DEFAULT 0")
            conn.commit()
        except:
            pass

    # Migrate canonical policy rules to database (idempotent)
    try:
        from app.policy_engine.canonical_policy_loader import migrate_to_db
        migrated = migrate_to_db(skip_init=True)
        print(f"[database] Migrated {migrated} canonical policy rules to database")
    except Exception as e:
        print(f"[database] Policy migration skipped: {e}")

    conn.close()


class SupportTicketRepository:

    @staticmethod
    def create_ticket(user_id: str, user_name: str, user_email: str, subject: str, description: str) -> Dict[str, Any]:
        init_db()
        conn, db_type = get_db_connection()
        cursor = conn.cursor()

        ticket_id = f"tkt-{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc).isoformat()

        if db_type == "postgres":
            cursor.execute("""
                INSERT INTO support_tickets (id, user_id, user_name, user_email, subject, description, status, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, 'open', %s)
            """, (ticket_id, user_id, user_name, user_email, subject, description, created_at))
        else:
            cursor.execute("""
                INSERT INTO support_tickets (id, user_id, user_name, user_email, subject, description, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'open', ?)
            """, (ticket_id, user_id, user_name, user_email, subject, description, created_at))

        conn.commit()
        conn.close()

        return {
            "ticket_id": ticket_id,
            "user_id": user_id,
            "user_name": user_name,
            "user_email": user_email,
            "subject": subject,
            "description": description,
            "status": "open",
            "created_at": created_at
        }




def hash_password(password: str) -> str:
    """Hashes password securely using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored bcrypt hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False


def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"


class UserRepository:

    @staticmethod
    def create_user(
        first_name: str,
        last_name: str,
        username: str,
        email: str,
        password: Optional[str] = None,
        provider: str = "email"
    ) -> Dict[str, Any]:
        init_db()
        conn, db_type = get_db_connection()
        cursor = conn.cursor()

        user_id = f"usr-{uuid.uuid4().hex[:12]}"
        password_hash = hash_password(password) if password else None
        otp_code = generate_otp()
        
        # OTP expires in 10 minutes
        code_expires_at_dt = datetime.now(timezone.utc) + timedelta(minutes=10)
        code_expires_at_str = code_expires_at_dt.isoformat()
        created_at_dt = datetime.now(timezone.utc)
        created_at_str = created_at_dt.isoformat()

        # Check existing user by email
        existing = UserRepository.get_by_email(email)

        if existing:
            # Update OTP & password if existing unverified account
            if db_type == "postgres":
                cursor.execute(
                    """
                    UPDATE users 
                    SET verification_code = %s, code_expires_at = %s, password_hash = %s, first_name = %s, last_name = %s, username = %s
                    WHERE email = %s
                    """,
                    (otp_code, code_expires_at_dt, password_hash, first_name, last_name, username, email.lower())
                )
            else:
                cursor.execute(
                    """
                    UPDATE users 
                    SET verification_code = ?, code_expires_at = ?, password_hash = ?, first_name = ?, last_name = ?, username = ?
                    WHERE email = ?
                    """,
                    (otp_code, code_expires_at_str, password_hash, first_name, last_name, username, email.lower())
                )
            conn.commit()
            conn.close()
            existing["verification_code"] = otp_code
            existing["code_expires_at"] = code_expires_at_str
            return existing

        if db_type == "postgres":
            cursor.execute("""
                INSERT INTO users (id, first_name, last_name, username, email, password_hash, auth_provider, is_verified, verification_code, code_expires_at, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, FALSE, %s, %s, %s)
            """, (user_id, first_name, last_name, username, email.lower(), password_hash, provider, otp_code, code_expires_at_dt, created_at_dt))
        else:
            cursor.execute("""
                INSERT INTO users (id, first_name, last_name, username, email, password_hash, auth_provider, is_verified, verification_code, code_expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
            """, (user_id, first_name, last_name, username, email.lower(), password_hash, provider, otp_code, code_expires_at_str, created_at_str))

        conn.commit()
        conn.close()

        return {
            "id": user_id,
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "email": email.lower(),
            "is_verified": False,
            "verification_code": otp_code,
            "code_expires_at": code_expires_at_str,
            "auth_provider": provider,
            "created_at": created_at_str
        }

    @staticmethod
    def get_by_email(email: str) -> Optional[Dict[str, Any]]:
        init_db()
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        if db_type == "postgres":
            cursor.execute("SELECT * FROM users WHERE email = %s", (email.lower(),))
        else:
            cursor.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        res = dict(row)
        res["provider"] = res.get("auth_provider", res.get("provider", "email"))
        return res

    @staticmethod
    def verify_otp(email: str, code: str) -> bool:
        user = UserRepository.get_by_email(email)
        if not user:
            print(f"[OTP DEBUG] User not found for email: {email}")
            return False

        stored_code = user.get("verification_code")
        submitted_code = code.strip()

        print(f"[OTP DEBUG] Submitted code: '{submitted_code}' | Stored code: '{stored_code}'")

        if not stored_code or stored_code != submitted_code:
            print(f"[OTP DEBUG] Mismatch! Submitted '{submitted_code}' != Stored '{stored_code}'")
            return False

        # Check expiration (10 minutes)
        expires_at_raw = user.get("code_expires_at")
        now_utc = datetime.now(timezone.utc)

        if expires_at_raw:
            if isinstance(expires_at_raw, str):
                try:
                    expires_at = datetime.fromisoformat(expires_at_raw)
                except Exception:
                    expires_at = now_utc + timedelta(minutes=10)
            else:
                expires_at = expires_at_raw

            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            print(f"[OTP DEBUG] Now (UTC): {now_utc.isoformat()} | Expires At (UTC): {expires_at.isoformat()}")

            if now_utc > expires_at:
                print(f"[OTP DEBUG] Code EXPIRED! Current time {now_utc.isoformat()} > {expires_at.isoformat()}")
                return False

        print(f"[OTP DEBUG] OTP Verification SUCCESS for email: {email}")

        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        if db_type == "postgres":
            cursor.execute(
                "UPDATE users SET is_verified = TRUE, verification_code = NULL, code_expires_at = NULL WHERE email = %s",
                (email.lower(),)
            )
        else:
            cursor.execute(
                "UPDATE users SET is_verified = 1, verification_code = NULL, code_expires_at = NULL WHERE email = ?",
                (email.lower(),)
            )
        conn.commit()
        conn.close()
        return True

    @staticmethod
    def check_otp(email: str, code: str) -> bool:
        """
        Non-destructive OTP check: returns True iff the code matches and is
        not expired, but does NOT clear the stored code. Used by the reset-
        password flow so the user can verify the code first, see the password
        fields, and then submit a single reset-password call that consumes
        the OTP.
        """
        user = UserRepository.get_by_email(email)
        if not user:
            return False
        stored_code = user.get("verification_code")
        if not stored_code or stored_code.strip() != code.strip():
            return False
        expires_at_raw = user.get("code_expires_at")
        if not expires_at_raw:
            return True
        now_utc = datetime.now(timezone.utc)
        if isinstance(expires_at_raw, str):
            try:
                expires_at = datetime.fromisoformat(expires_at_raw)
            except Exception:
                return True
        else:
            expires_at = expires_at_raw
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return now_utc <= expires_at


    @staticmethod
    def get_by_username(username: str) -> Optional[Dict[str, Any]]:
        init_db()
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        if db_type == "postgres":
            cursor.execute("SELECT * FROM users WHERE LOWER(username) = %s", (username.lower(),))
        else:
            cursor.execute("SELECT * FROM users WHERE LOWER(username) = ?", (username.lower(),))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def update_profile(
        email: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        username: Optional[str] = None
    ) -> Dict[str, Any]:
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        user = UserRepository.get_by_email(email)
        if not user:
            conn.close()
            raise ValueError("User not found")

        new_first = first_name.strip() if first_name else user["first_name"]
        new_last = last_name.strip() if last_name is not None else user.get("last_name", "")
        new_user = username.strip() if username else user.get("username", email.split("@")[0])

        if db_type == "postgres":
            cursor.execute(
                "UPDATE users SET first_name = %s, last_name = %s, username = %s WHERE LOWER(email) = %s",
                (new_first, new_last, new_user, email.lower())
            )
        else:
            cursor.execute(
                "UPDATE users SET first_name = ?, last_name = ?, username = ? WHERE LOWER(email) = ?",
                (new_first, new_last, new_user, email.lower())
            )
        conn.commit()
        conn.close()
        return UserRepository.get_by_email(email)


    @staticmethod
    def set_verified(email: str):
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        if db_type == "postgres":
            cursor.execute(
                "UPDATE users SET is_verified = TRUE, verification_code = NULL, code_expires_at = NULL WHERE email = %s",
                (email.lower(),)
            )
        else:
            cursor.execute(
                "UPDATE users SET is_verified = 1, verification_code = NULL, code_expires_at = NULL WHERE email = ?",
                (email.lower(),)
            )
        conn.commit()
        conn.close()

    @staticmethod
    def update_password(email: str, new_password: str) -> bool:
        """Hash and persist a new password for the user. Returns True iff a row was updated."""
        if not new_password:
            return False
        password_hash = hash_password(new_password)
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        if db_type == "postgres":
            cursor.execute(
                "UPDATE users SET password_hash = %s WHERE LOWER(email) = %s",
                (password_hash, email.strip().lower())
            )
        else:
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE LOWER(email) = ?",
                (password_hash, email.strip().lower())
            )
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

