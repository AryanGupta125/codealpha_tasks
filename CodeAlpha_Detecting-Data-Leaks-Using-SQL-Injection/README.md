# Detecting-Data-Leaks-Using-SQL-Injection
This project is a lightweight, internet-accessible cloud system designed to protect sensitive user data from data leaks and SQL Injection (SQLi) vulnerabilities. By combining modern cryptographic standards with a novel runtime access control mechanism, the system ensures that backend databases remain secure even when processing dynamic queries.

Live Public URL of this Project - https://detecting-data-leaks-using-sql-inje.vercel.app/
# SQL Injection Detection & Security System

---

## 1. LANGUAGE USED

**Python 3** — with these libraries:

- `flask` → lightweight web framework for the API and dashboard
- `mysql-connector-python` → connects to AWS RDS MySQL cloud database
- `cryptography` → AES-256-GCM encryption for sensitive data
- `hashlib` → SHA-256 password hashing (built into Python)
- `re` → regex-based SQL injection pattern detection (built into Python)
- `os` → reads environment variables for credentials (built into Python)

---

## 2. OVERVIEW OF THE CODE

The system has **3 files** and **2 security layers**:

---

### Double-Layer Security Protocol

Every incoming request passes through BOTH layers:

LAYER 2 (runs first) → SQL Injection Shield
    Scans input against 20+ attack patterns using regex.
    If malicious → BLOCKED immediately. Request never reaches DB.

LAYER 1 (runs second) → AES-256 Encryption + Parameterized Queries
    Email encrypted with AES-256-GCM before storing.
    Password hashed with SHA-256 + salt.
    All DB queries use %s placeholders (never string concat).

---

### `security_system.py` — Core Logic

**AES-256-GCM Encryption:**
- `encrypt_data(text)` → encrypts using AES-256-GCM (nonce + auth tag + ciphertext → base64)
- `decrypt_data(encrypted)` → decrypts and verifies authentication tag
- `hash_password(password)` → SHA-256 hash with salt for secure password storage

**SQL Injection Detection:**
- `detect_sql_injection(input)` → scans against 20+ regex patterns
- Catches: `OR 1=1`, `UNION SELECT`, `DROP TABLE`, `SLEEP()`, `--`, `/**/`, hex encoding, stacked queries and more
- `sanitize_input(input)` → secondary defense: escapes special characters

**Double-Layer Security Functions:**
- `secure_register(username, email, password)` → Layer 2 scan → Layer 1 encrypt → save to DB
- `secure_login(username, password)` → Layer 2 scan → Layer 1 verify credentials
- `test_injection(input)` → standalone injection scanner for demo/testing

**Database Tables on AWS RDS MySQL:**
- `users` → stores username, AES-256 encrypted email, SHA-256 hashed password
- `security_log` → records every request with risk level and detection result
- `detected_attacks` → logs all confirmed injection attempts

---

### `app.py` — Flask Web Server

Exposes 7 REST API endpoints that the dashboard calls:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Serves dashboard HTML |
| POST | `/api/register` | Secure user registration |
| POST | `/api/login` | Secure user login |
| POST | `/api/test-injection` | Test any input for injection |
| GET | `/api/users` | Fetch all users (decrypted) |
| GET | `/api/logs` | Fetch security log |
| GET | `/api/attacks` | Fetch confirmed attacks |
| GET | `/api/stats` | Fetch summary statistics |

---

### `static/index.html` — Web Dashboard

6-tab browser dashboard:
- **Register** — secure registration form with security layers visual
- **Login** — login form with pre-loaded SQL injection examples to try
- **Injection Tester** — test any string against the detection engine live
- **Users DB** — view all registered users with decrypted emails
- **Security Logs** — full history of every request with risk levels
- **Attacks** — table of all detected and blocked injection attempts

---


## 3. SECURITY FEATURES SUMMARY

| Feature | Implementation |
|---|---|
| AES-256 Encryption | Email encrypted with AES-256-GCM before DB storage |
| Password Security | SHA-256 hash + salt — never stored in plaintext |
| SQL Injection Detection | 20+ regex patterns covering all major attack types |
| Double-Layer Protocol | Injection scan always runs before any DB operation |
| Parameterized Queries | All SQL uses `%s` placeholders — never string concat |
| Attack Logging | Every injection attempt logged with pattern and risk level |
| Input Sanitization | Secondary defense — special characters escaped |
| Audit Trail | Full security log of every request with timestamp |

---

## 4. CLOUD ARCHITECTURE

| Component | Technology | Purpose |
|---|---|---|
| Web Framework | Flask (Python) | API + serves dashboard |
| Database | AWS RDS MySQL | Cloud storage for all data |
| Hosting | Render.com | Makes app live on internet |
| Code Storage | GitHub | Version control + Render source |
| Encryption | AES-256-GCM | Protects sensitive user data |

---

Built with Python + Flask + AES-256 + AWS RDS MySQL.
