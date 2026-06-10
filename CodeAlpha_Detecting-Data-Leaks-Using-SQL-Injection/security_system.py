"""
Task 2: Detecting Data Leaks Using SQL Injection
Security System — Core Logic
"""

import os
import re
import hashlib
import base64
import mysql.connector
from mysql.connector import Error
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


#  AES-256 ENCRYPTION (Layer 1 Security)
# AES-256 requires a 32-byte key — read from environment variable
def get_aes_key() -> bytes:
    """Get AES-256 key from environment. Must be exactly 32 bytes."""
    key = os.environ.get("AES_SECRET_KEY", "ThisIsA32ByteSecretKey!!SECURE!!")
    return key[:32].encode("utf-8")


def encrypt_data(plaintext: str) -> str:
    """
    Encrypt sensitive data using AES-256-GCM.
    GCM mode provides both encryption AND authentication.
    Returns base64-encoded string: nonce + tag + ciphertext
    """
    key = get_aes_key()
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    # Combine nonce + auth tag + ciphertext → encode to base64 for storage
    encrypted = base64.b64encode(nonce + encryptor.tag + ciphertext).decode()
    return encrypted


def decrypt_data(encrypted: str) -> str:
    """
    Decrypt AES-256-GCM encrypted data.
    Verifies authentication tag to detect tampering.
    """
    try:
        key = get_aes_key()
        raw = base64.b64decode(encrypted.encode())
        nonce      = raw[:12]   # first 12 bytes
        tag        = raw[12:28] # next 16 bytes
        ciphertext = raw[28:]   # rest is ciphertext

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
    except Exception:
        return "[DECRYPTION FAILED]"


def hash_password(password: str) -> str:
    """Hash password using SHA-256 with a salt for secure storage."""
    salt = os.environ.get("PASSWORD_SALT", "SECURE_SALT_2024")
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


#  SQL INJECTION DETECTION (Layer 2 Security)

# Comprehensive list of SQL injection patterns
SQL_INJECTION_PATTERNS = [
    r"(\bOR\b|\bAND\b)\s+[\w'\"]+\s*=\s*[\w'\"]+",   # OR 1=1, AND 'a'='a'
    r"--\s",                                             # SQL comment --
    r"/\*.*?\*/",                                        # Block comment /* */
    r";.*?(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)",     # Stacked queries
    r"\bDROP\b",                                         # DROP TABLE
    r"\bDELETE\b\s+\bFROM\b",                          # DELETE FROM
    r"\bINSERT\b\s+\bINTO\b",                           # INSERT INTO
    r"\bUNION\b\s+\bSELECT\b",                         # UNION SELECT
    r"\bEXEC\b|\bEXECUTE\b",                            # EXEC commands
    r"\bxp_\w+",                                         # SQL Server extended procs
    r"'\s*;\s*",                                         # '; end of statement
    r"\bSLEEP\b\s*\(",                                  # Time-based: SLEEP()
    r"\bWAITFOR\b",                                      # WAITFOR DELAY
    r"\bBENCHMARK\b\s*\(",                              # BENCHMARK()
    r"0x[0-9a-fA-F]+",                                  # Hex encoding
    r"\bCHAR\b\s*\(",                                   # CHAR() function
    r"\bCONCAT\b\s*\(",                                 # CONCAT() function
    r"\bINFORMATION_SCHEMA\b",                          # Schema enumeration
    r"\bSYSOBJECTS\b|\bSYSCOLUMNS\b",                 # SQL Server tables
    r"'\s*OR\s*'",                                       # Classic ' OR '
    r'"\s*OR\s*"',                                       # Classic " OR "
]


def detect_sql_injection(user_input: str) -> dict:
    """
    Layer 2: Scan input for SQL injection patterns.
    Returns detection result with details.
    """
    if not user_input:
        return {"is_malicious": False, "pattern_matched": None, "risk_level": "NONE"}

    input_upper = user_input.upper()

    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, input_upper, re.IGNORECASE):
            return {
                "is_malicious": True,
                "pattern_matched": pattern,
                "risk_level": "HIGH",
                "detail": f"SQL injection pattern detected: {pattern}"
            }

    # Check for suspicious character combinations
    suspicious_chars = ["'", '"', ";", "--", "/*", "*/", "\\x", "%27", "%22"]
    for char in suspicious_chars:
        if char in user_input:
            return {
                "is_malicious": True,
                "pattern_matched": char,
                "risk_level": "MEDIUM",
                "detail": f"Suspicious character detected: {char}"
            }

    return {"is_malicious": False, "pattern_matched": None, "risk_level": "NONE"}


def sanitize_input(user_input: str) -> str:
    """Sanitize input by escaping special characters as a secondary defense."""
    if not user_input:
        return ""
    # Remove null bytes
    sanitized = user_input.replace("\x00", "")
    # Escape single quotes
    sanitized = sanitized.replace("'", "''")
    # Strip leading/trailing whitespace
    return sanitized.strip()


#  DATABASE CONNECTION — AWS RDS MySQL

def get_connection():
    """Connect to AWS RDS MySQL using environment variables."""
    try:
        conn = mysql.connector.connect(
            host     = os.environ.get("DB_HOST"),
            port     = int(os.environ.get("DB_PORT", 3306)),
            user     = os.environ.get("DB_USER"),
            password = os.environ.get("DB_PASSWORD"),
            database = os.environ.get("DB_NAME"),
        )
        return conn
    except Error as e:
        print(f"[DB ERROR] {e}")
        raise


def init_db():
    """Auto-create database and tables on AWS RDS MySQL."""
    db_name = os.environ.get("DB_NAME", "security_db")

    # Step 1: Create database if not exists
    try:
        temp_conn = mysql.connector.connect(
            host     = os.environ.get("DB_HOST"),
            port     = int(os.environ.get("DB_PORT", 3306)),
            user     = os.environ.get("DB_USER"),
            password = os.environ.get("DB_PASSWORD"),
        )
        temp_cursor = temp_conn.cursor()
        temp_cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
        temp_conn.commit()
        temp_cursor.close()
        temp_conn.close()
        print(f"[DB] Database '{db_name}' ready.")
    except Error as e:
        print(f"[DB ERROR] Could not create database: {e}")
        raise

    # Step 2: Create tables
    conn = get_connection()
    cursor = conn.cursor()

    # Users table — stores AES-256 encrypted credentials
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INT AUTO_INCREMENT PRIMARY KEY,
            username        VARCHAR(100) UNIQUE NOT NULL,
            encrypted_email TEXT NOT NULL,
            password_hash   VARCHAR(64) NOT NULL,
            created_at      DATETIME NOT NULL
        )
    """)

    # Security log — records every access attempt with injection analysis
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_log (
            id              INT AUTO_INCREMENT PRIMARY KEY,
            input_data      TEXT NOT NULL,
            action          VARCHAR(50) NOT NULL,
            risk_level      VARCHAR(10) NOT NULL,
            is_malicious    BOOLEAN NOT NULL,
            pattern_matched TEXT,
            ip_address      VARCHAR(45),
            attempted_at    DATETIME NOT NULL
        )
    """)

    # Data leaks table — records detected injection attempts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detected_attacks (
            id              INT AUTO_INCREMENT PRIMARY KEY,
            attack_input    TEXT NOT NULL,
            pattern_matched TEXT NOT NULL,
            risk_level      VARCHAR(10) NOT NULL,
            blocked_at      DATETIME NOT NULL
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()
    print("[DB] All tables initialized successfully.")


#  DOUBLE-LAYER SECURITY PROTOCOL

def secure_register(username: str, email: str, password: str, ip: str = "unknown") -> dict:
    """
    Register a new user with double-layer security:
    Layer 1 → AES-256 encrypt the email
    Layer 2 → SQL injection check on all inputs
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── LAYER 2: SQL Injection Check first ──
    for field_name, field_value in [("username", username), ("email", email), ("password", password)]:
        detection = detect_sql_injection(field_value)
        log_attempt(field_value, "REGISTER", detection, ip)
        if detection["is_malicious"]:
            log_attack(field_value, detection)
            return {
                "success": False,
                "status": "BLOCKED",
                "risk_level": detection["risk_level"],
                "message": f"SQL injection detected in {field_name} field. Access denied.",
                "layer": "Layer 2 — SQL Injection Shield"
            }

    # ── LAYER 1: AES-256 Encrypt sensitive data ──
    encrypted_email = encrypt_data(email)
    password_hash   = hash_password(password)
    clean_username  = sanitize_input(username)

    # Write to AWS RDS using parameterized query (not string concat — injection safe)
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, encrypted_email, password_hash, created_at) VALUES (%s, %s, %s, %s)",
            (clean_username, encrypted_email, password_hash, timestamp)
        )
        conn.commit()
        cursor.close()
        conn.close()

        return {
            "success": True,
            "status": "REGISTERED",
            "message": f"User '{username}' registered securely.",
            "security": "AES-256 encrypted · SQL injection safe · Parameterized query",
            "layer": "Both layers passed ✓"
        }
    except Error as e:
        if "Duplicate entry" in str(e):
            return {"success": False, "status": "ERROR", "message": "Username already exists."}
        return {"success": False, "status": "ERROR", "message": str(e)}


def secure_login(username: str, password: str, ip: str = "unknown") -> dict:
    """
    Login with double-layer security:
    Layer 1 → Verify encrypted credentials
    Layer 2 → SQL injection check on inputs
    """
    # ── LAYER 2: SQL Injection Check ──
    for field_name, field_value in [("username", username), ("password", password)]:
        detection = detect_sql_injection(field_value)
        log_attempt(field_value, "LOGIN", detection, ip)
        if detection["is_malicious"]:
            log_attack(field_value, detection)
            return {
                "success": False,
                "status": "BLOCKED",
                "risk_level": detection["risk_level"],
                "message": f"SQL injection detected in {field_name}. Access denied.",
                "layer": "Layer 2 — SQL Injection Shield"
            }

    # ── LAYER 1: Verify credentials ──
    password_hash = hash_password(password)
    clean_username = sanitize_input(username)

    try:
        conn = get_connection()
        cursor = conn.cursor()
        # Parameterized query — safe from injection
        cursor.execute(
            "SELECT id, username FROM users WHERE username = %s AND password_hash = %s",
            (clean_username, password_hash)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            return {
                "success": True,
                "status": "LOGIN_SUCCESS",
                "message": f"Welcome back, {username}!",
                "layer": "Both layers passed ✓"
            }
        else:
            return {
                "success": False,
                "status": "LOGIN_FAILED",
                "message": "Invalid username or password.",
                "layer": "Layer 1 — Credential Verification"
            }
    except Error as e:
        return {"success": False, "status": "ERROR", "message": str(e)}


def test_injection(test_input: str, ip: str = "unknown") -> dict:
    """
    Test any input string for SQL injection — for demo/showcase purposes.
    """
    detection = detect_sql_injection(test_input)
    log_attempt(test_input, "INJECTION_TEST", detection, ip)
    if detection["is_malicious"]:
        log_attack(test_input, detection)
    return {
        "input": test_input,
        "is_malicious": detection["is_malicious"],
        "risk_level": detection["risk_level"],
        "detail": detection.get("detail", "Input is clean"),
        "pattern_matched": detection.get("pattern_matched")
    }


#  LOGGING HELPERS

def log_attempt(input_data: str, action: str, detection: dict, ip: str):
    """Log every access attempt to security_log table."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO security_log
               (input_data, action, risk_level, is_malicious, pattern_matched, ip_address, attempted_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (
                input_data[:500],
                action,
                detection.get("risk_level", "NONE"),
                detection.get("is_malicious", False),
                detection.get("pattern_matched"),
                ip,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception:
        pass  # Don't crash the app if logging fails


def log_attack(attack_input: str, detection: dict):
    """Log confirmed attacks to detected_attacks table."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO detected_attacks (attack_input, pattern_matched, risk_level, blocked_at) VALUES (%s, %s, %s, %s)",
            (
                attack_input[:500],
                str(detection.get("pattern_matched", "")),
                detection.get("risk_level", "HIGH"),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception:
        pass


#  DATA FETCH FUNCTIONS

def get_users() -> list:
    """Fetch all users — emails shown decrypted for admin view."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, encrypted_email, created_at FROM users ORDER BY id DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [{
        "id": r[0],
        "username": r[1],
        "email": decrypt_data(r[2]),
        "created_at": str(r[3])
    } for r in rows]


def get_security_logs() -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, input_data, action, risk_level, is_malicious, attempted_at FROM security_log ORDER BY id DESC LIMIT 100"
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [{"id": r[0], "input": r[1], "action": r[2], "risk": r[3], "malicious": bool(r[4]), "time": str(r[5])} for r in rows]


def get_attacks() -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, attack_input, pattern_matched, risk_level, blocked_at FROM detected_attacks ORDER BY id DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [{"id": r[0], "input": r[1], "pattern": r[2], "risk": r[3], "time": str(r[4])} for r in rows]


def get_stats() -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM security_log")
    total_attempts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM security_log WHERE is_malicious = TRUE")
    blocked = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM detected_attacks")
    attacks = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return {
        "total_users": total_users,
        "total_attempts": total_attempts,
        "blocked_attempts": blocked,
        "attacks_detected": attacks,
        "safe_attempts": total_attempts - blocked
    }
