import os


class Config:
    # ── Core ──────────────────────────────────────────
    SECRET_KEY = os.environ.get(
        'SECRET_KEY') or 'dev-secret-key-change-in-production'

    # ── Database ──────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = 'sqlite:///scanner.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Scan Settings ─────────────────────────────────
    DEFAULT_SCAN_TIMEOUT = 300
    MAX_HOSTS_PER_SCAN = 254

    # ── Email Alerts ──────────────────────────────────
    # Fill in your Gmail address and App Password below
    # To get Gmail App Password:
    # 1. Go to myaccount.google.com
    # 2. Security → 2-Step Verification → App Passwords
    # 3. Create one called "NetScanner"
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get(
        'MAIL_USERNAME') or 'manithbanula2004@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'mypetiskumi'
    MAIL_SENDER = os.environ.get(
        'MAIL_USERNAME') or 'manithbanula2004@gmail.com'
    ALERT_EMAIL = os.environ.get('ALERT_EMAIL') or 'manithbanular@gmail.com'

    # ── CVE Settings ──────────────────────────────────
    # Free NVD API — no key needed but rate limited
    # Get a free key at https://nvd.nist.gov/developers/request-an-api-key
    # for faster lookups (remove the sleep delays)
    NVD_API_KEY = os.environ.get('NVD_API_KEY') or None
    CVE_CACHE_HOURS = 24   # cache CVE results for 24 hours

    # ── Scheduler ─────────────────────────────────────
    SCHEDULER_ENABLED = True
    SCHEDULER_INTERVAL_HOURS = 24  # run scheduled scans every 24 hours
