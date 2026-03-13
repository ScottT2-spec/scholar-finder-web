"""
ScholarFinder Web App — Flask Backend
Built by Scott Antwi | Alpha Global Minds 🌍

Features:
- User signup/login with sessions
- User profiles (country, field, education level)
- Scholarship matching based on profile
- Save/bookmark scholarships
- Dashboard with saved items + upcoming deadlines
- API endpoints for all data
- Admin panel
"""

import os
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, request, jsonify, render_template, redirect,
    url_for, session, flash, g, send_from_directory
)
import urllib.request
import urllib.parse
import urllib.error
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load .env file if present (for local dev)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
if os.path.exists(_env_path):
    with open(_env_path) as _ef:
        for _line in _ef:
            _line = _line.strip()
            if _line and not _line.startswith('#') and '=' in _line:
                _k, _v = _line.split('=', 1)
                os.environ.setdefault(_k.strip(), _v.strip())

app = Flask(__name__)
# Persistent secret key (survives restarts)
_secret_path = os.path.join(os.path.dirname(__file__), '.secret_key')
if os.path.exists(_secret_path):
    with open(_secret_path, 'r') as _f:
        app.secret_key = _f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(_secret_path, 'w') as _f:
        _f.write(app.secret_key)

# Security settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

# Webhook secret for scholarship management
WEBHOOK_SECRET = 'sf_whk_' + hashlib.sha256(app.secret_key.encode()).hexdigest()[:32]

# ============================================
# DATABASE
# ============================================
DB_PATH = os.path.join(os.path.dirname(__file__), 'scholarweb.db')
# Use local data/ folder (works on PythonAnywhere and local)
_local_data = os.path.join(os.path.dirname(__file__), 'data')
_bot_data = os.path.join(os.path.dirname(__file__), '..', 'scholarbot')
DATA_DIR = _local_data if os.path.isdir(_local_data) else _bot_data

ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', '')

# Email verification config
SMTP_EMAIL = os.environ.get('SMTP_EMAIL', '')
SMTP_APP_PASSWORD = os.environ.get('SMTP_APP_PASSWORD', '')
VERIFICATION_EXPIRY_MINUTES = 1  # 1 minute

# Groq AI config — keys loaded from .env, with automatic rotation on 429
GROQ_API_KEYS = [
    os.environ.get('GROQ_KEY_1', ''),  # account 2 (primary)
    os.environ.get('GROQ_KEY_2', ''),  # account 3
    os.environ.get('GROQ_KEY_3', ''),  # account 3
    os.environ.get('GROQ_KEY_4', ''),  # account 4
    os.environ.get('GROQ_KEY_5', ''),  # account 5
    os.environ.get('GROQ_KEY_6', ''),  # account 6
    os.environ.get('GROQ_KEY_7', ''),  # account 7
    os.environ.get('GROQ_KEY_8', ''),  # account 8
    os.environ.get('GROQ_KEY_9', ''),  # account 9
    os.environ.get('GROQ_KEY_10', ''), # account 10
    os.environ.get('GROQ_KEY_11', ''), # account 11
    os.environ.get('GROQ_KEY_12', ''), # account 12
]
GROQ_API_KEYS = [k for k in GROQ_API_KEYS if k]  # remove empty
_groq_key_index = 0
_groq_dead_keys = {}  # key -> timestamp when it will be available again

def get_groq_key():
    """Round-robin key selection."""
    global _groq_key_index
    key = GROQ_API_KEYS[_groq_key_index % len(GROQ_API_KEYS)]
    _groq_key_index += 1
    return key

def _make_groq_request(key, payload_bytes, timeout):
    """Make a single Groq API call with the given key."""
    req = urllib.request.Request(
        'https://api.groq.com/openai/v1/chat/completions',
        data=payload_bytes,
        headers={
            'Authorization': 'Bearer ' + key,
            'Content-Type': 'application/json',
            'User-Agent': 'ScholarFinder/1.0',
            'Accept': 'application/json',
        }
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))

def _parse_retry_after(e):
    """Extract retry-after seconds from a 429 response."""
    try:
        val = e.headers.get('retry-after', '')
        if val:
            return float(val)
    except (ValueError, TypeError):
        pass
    return 60  # default cooldown if header missing

def call_groq(payload_bytes, timeout=30):
    """Call Groq API with automatic key rotation on 429.
    
    How it works:
    1. Tries all keys round-robin, instantly skipping to the next on 429.
    2. Reads Groq's retry-after header to know exactly when each key recovers.
    3. If all keys are limited, waits for the soonest one to recover and retries.
    4. Keeps retrying up to 30 seconds total — catches keys that come back mid-wait.
    5. Works with any number of keys (1 to 100).
    """
    import time as _t
    start = _t.time()
    max_wait = 30  # total seconds we're willing to wait

    # Clean up recovered keys
    now = _t.time()
    for k in list(_groq_dead_keys):
        if now >= _groq_dead_keys[k]:
            del _groq_dead_keys[k]

    last_error = None

    while (_t.time() - start) < max_wait:
        # Try every key once this round
        tried_any = False
        for _ in range(len(GROQ_API_KEYS)):
            key = get_groq_key()

            # Skip keys that are still cooling down
            now = _t.time()
            if key in _groq_dead_keys and now < _groq_dead_keys[key]:
                continue

            # Key is available — try it
            tried_any = True
            try:
                return _make_groq_request(key, payload_bytes, timeout)
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    # Mark key as dead until retry-after expires
                    retry_after = _parse_retry_after(e)
                    _groq_dead_keys[key] = _t.time() + retry_after
                    last_error = e
                    continue  # immediately try next key
                raise  # non-429 errors bubble up

        # All keys were either skipped or returned 429
        # Find the soonest key to recover
        if _groq_dead_keys:
            soonest = min(_groq_dead_keys.values())
            wait_needed = soonest - _t.time()
            if wait_needed > 0 and (_t.time() - start + wait_needed) < max_wait:
                _t.sleep(min(wait_needed + 0.5, 5))  # wait for it, cap at 5s per sleep
                # Remove recovered keys
                now = _t.time()
                for k in list(_groq_dead_keys):
                    if now >= _groq_dead_keys[k]:
                        del _groq_dead_keys[k]
                continue  # retry the loop
            else:
                break  # would exceed max_wait
        else:
            break  # no dead keys but nothing worked — shouldn't happen

    # All keys exhausted and max wait exceeded
    raise last_error or Exception('All Groq API keys are rate-limited. Please try again shortly.')

GROQ_API_KEY = GROQ_API_KEYS[0] if GROQ_API_KEYS else ''
GROQ_MODEL = 'llama-3.3-70b-versatile'

# ============================================
# FIELD OF STUDY VALIDATION
# ============================================
VALID_FIELDS = {
    # STEM
    'computer science', 'software engineering', 'information technology', 'data science',
    'artificial intelligence', 'machine learning', 'cybersecurity', 'web development',
    'mathematics', 'statistics', 'physics', 'chemistry', 'biology', 'biochemistry',
    'biotechnology', 'bioinformatics', 'environmental science', 'geology', 'geosciences',
    'astronomy', 'astrophysics', 'materials science', 'nanotechnology',
    'engineering', 'mechanical engineering', 'electrical engineering', 'civil engineering',
    'chemical engineering', 'aerospace engineering', 'biomedical engineering',
    'industrial engineering', 'petroleum engineering', 'mining engineering',
    'agricultural engineering', 'marine engineering', 'nuclear engineering',
    'robotics', 'mechatronics', 'telecommunications',
    # Medicine & Health
    'medicine', 'nursing', 'pharmacy', 'dentistry', 'veterinary medicine',
    'public health', 'epidemiology', 'biomedical sciences', 'physiotherapy',
    'occupational therapy', 'radiology', 'pathology', 'nutrition', 'dietetics',
    'midwifery', 'optometry', 'speech therapy', 'mental health', 'psychology',
    'clinical psychology', 'neuroscience', 'anatomy', 'immunology', 'microbiology',
    'medical laboratory science', 'health informatics', 'global health',
    # Business & Economics
    'business', 'business administration', 'accounting', 'finance', 'economics',
    'marketing', 'management', 'entrepreneurship', 'human resources',
    'supply chain management', 'logistics', 'international business',
    'actuarial science', 'banking', 'insurance', 'real estate',
    'project management', 'operations management', 'commerce',
    # Law & Politics
    'law', 'international law', 'criminal justice', 'political science',
    'international relations', 'public administration', 'public policy',
    'diplomacy', 'governance', 'human rights',
    # Arts & Humanities
    'english', 'literature', 'history', 'philosophy', 'linguistics',
    'creative writing', 'journalism', 'media studies', 'communication',
    'film studies', 'theater', 'performing arts', 'music', 'fine arts',
    'visual arts', 'graphic design', 'animation', 'photography',
    'art history', 'cultural studies', 'religious studies', 'theology',
    'classical studies', 'gender studies', 'african studies', 'asian studies',
    # Social Sciences
    'sociology', 'anthropology', 'geography', 'demography',
    'social work', 'criminology', 'archaeology', 'urban planning',
    'development studies', 'peace studies', 'conflict resolution',
    # Education
    'education', 'teaching', 'early childhood education', 'special education',
    'educational technology', 'curriculum development', 'educational psychology',
    'higher education', 'adult education', 'stem education',
    # Agriculture & Environment
    'agriculture', 'agronomy', 'horticulture', 'animal science',
    'fisheries', 'forestry', 'food science', 'food technology',
    'environmental management', 'climate science', 'sustainability',
    'renewable energy', 'water resources', 'wildlife management', 'ecology',
    # Architecture & Design
    'architecture', 'interior design', 'urban design', 'landscape architecture',
    'industrial design', 'fashion design', 'textile design',
    # Sports & Hospitality
    'sport science', 'sport management', 'physical education',
    'hospitality management', 'tourism', 'hotel management', 'culinary arts',
    # Other
    'library science', 'archival studies', 'museum studies',
    'aviation', 'maritime studies', 'military science',
    'translation', 'interpreting', 'sign language',
}

# Also accept common variations and abbreviations
FIELD_ALIASES = {
    'cs': 'computer science', 'it': 'information technology', 'ai': 'artificial intelligence',
    'ml': 'machine learning', 'ee': 'electrical engineering', 'me': 'mechanical engineering',
    'ce': 'civil engineering', 'bme': 'biomedical engineering', 'mba': 'business administration',
    'hr': 'human resources', 'ir': 'international relations', 'pa': 'public administration',
    'med': 'medicine', 'pharm': 'pharmacy', 'econ': 'economics', 'polisci': 'political science',
    'comms': 'communication', 'psych': 'psychology', 'soc': 'sociology', 'bio': 'biology',
    'chem': 'chemistry', 'math': 'mathematics', 'stats': 'statistics', 'phys': 'physics',
    'eng': 'engineering', 'arch': 'architecture', 'enviro': 'environmental science',
    'agric': 'agriculture', 'mech eng': 'mechanical engineering', 'comp sci': 'computer science',
    'info tech': 'information technology', 'biz': 'business', 'acct': 'accounting',
    'nursing science': 'nursing', 'political studies': 'political science',
    'mass communication': 'communication', 'mass comm': 'communication',
    'electrical electronics engineering': 'electrical engineering',
    'computer engineering': 'computer science', 'ict': 'information technology',
}

def validate_field_of_study(field_str):
    """Check if the field of study is a real/recognized field.
    Returns (is_valid, cleaned_field_or_none, suggestion_or_none)
    
    STRICT MODE: only accepts fields in our known list or close matches.
    Anything not recognized is flagged — no guessing.
    """
    if not field_str or not field_str.strip():
        return False, None, None

    field = field_str.strip().lower()

    # Direct match
    if field in VALID_FIELDS:
        return True, field, None

    # Alias match
    if field in FIELD_ALIASES:
        return True, FIELD_ALIASES[field], None

    # Fuzzy: check if any valid field is contained in the input or vice versa
    for vf in VALID_FIELDS:
        if vf in field or field in vf:
            return True, vf, None

    # Word-level matching: check if any word in the input matches a word in valid fields
    input_words = set(field.split())
    for vf in VALID_FIELDS:
        vf_words = set(vf.split())
        # If they share a meaningful word (>3 chars), it's probably related
        common = input_words & vf_words
        if any(len(w) > 3 for w in common):
            return True, vf, None

    # Check against all words that appear in valid fields
    all_field_words = set()
    for vf in VALID_FIELDS:
        for w in vf.split():
            if len(w) > 3:
                all_field_words.add(w)
    for w in input_words:
        if len(w) > 3 and w in all_field_words:
            return True, field, 'partial'

    # If we get here, it's not recognized — flag it
    # Find the closest match to suggest
    best_match = None
    best_score = 0
    for vf in VALID_FIELDS:
        # Simple character overlap score
        field_set = set(field)
        vf_set = set(vf)
        overlap = len(field_set & vf_set) / max(len(field_set | vf_set), 1)
        if overlap > best_score:
            best_score = overlap
            best_match = vf

    return False, None, best_match if best_score > 0.4 else None



# Google OAuth config
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
GOOGLE_ANALYTICS_ID = os.environ.get('GOOGLE_ANALYTICS_ID', '')
ADSENSE_ID = os.environ.get('ADSENSE_ID', '')
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo'

# ============================================
# RATE LIMITING (SQLite-backed — survives restarts)
# ============================================
import time as _time

_MAX_LOGIN_ATTEMPTS = 5
_LOGIN_WINDOW = 300  # 5 minutes
_MAX_RESEND = 3
_RESEND_WINDOW = 300  # 5 minutes

def _init_rate_limit_table():
    """Create rate limit table if it doesn't exist"""
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS rate_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            category TEXT NOT NULL,
            timestamp REAL NOT NULL
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_rate_key_cat ON rate_limits(key, category)")
    db.commit()
    db.close()

def _check_rate(key, category, max_attempts, window_seconds):
    """Generic rate limit check using SQLite. Returns True if allowed."""
    now = _time.time()
    cutoff = now - window_seconds
    try:
        db = get_db()
        # Clean old entries
        db.execute('DELETE FROM rate_limits WHERE category = ? AND timestamp < ?', (category, cutoff))
        # Count recent attempts
        count = db.execute(
            'SELECT COUNT(*) FROM rate_limits WHERE key = ? AND category = ? AND timestamp >= ?',
            (key, category, cutoff)
        ).fetchone()[0]
        if count >= max_attempts:
            db.commit()
            return False
        # Record this attempt
        db.execute(
            'INSERT INTO rate_limits (key, category, timestamp) VALUES (?, ?, ?)',
            (key, category, now)
        )
        db.commit()
        return True
    except Exception:
        return True  # Fail open — don't block users if DB has issues

def check_rate_limit(ip):
    return _check_rate(ip, 'login', _MAX_LOGIN_ATTEMPTS, _LOGIN_WINDOW)

def check_resend_limit(email):
    return _check_rate(email, 'resend', _MAX_RESEND, _RESEND_WINDOW)

def generate_verification_code():
    """Generate a 6-digit verification code"""
    import random
    return str(random.randint(100000, 999999))

def send_verification_email(to_email, code, full_name=''):
    """Send verification code via Gmail SMTP"""
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f'ScholarFinder <{SMTP_EMAIL}>'
        msg['To'] = to_email
        msg['Subject'] = f'🎓 Your ScholarFinder Verification Code: {code}'

        name = full_name or 'there'
        html = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
            <div style="text-align: center; margin-bottom: 32px;">
                <h1 style="color: #6B21A8; font-size: 28px; margin: 0;">🎓 ScholarFinder</h1>
            </div>
            <div style="background: #f8f4ff; border-radius: 16px; padding: 32px; text-align: center;">
                <h2 style="color: #1a1a2e; margin: 0 0 8px;">Hey {name}! 👋</h2>
                <p style="color: #555; font-size: 15px; margin: 0 0 24px;">Enter this code to verify your email:</p>
                <div style="background: #6B21A8; color: white; font-size: 36px; font-weight: 800; letter-spacing: 12px; padding: 20px 32px; border-radius: 12px; display: inline-block; font-family: monospace;">
                    {code}
                </div>
                <p style="color: #888; font-size: 13px; margin-top: 24px;">This code expires in 1 minute.</p>
            </div>
            <p style="color: #999; font-size: 12px; text-align: center; margin-top: 24px;">
                If you didn't sign up for ScholarFinder, you can safely ignore this email.
            </p>
        </div>
        """
        text = f"Your ScholarFinder verification code is: {code}\nIt expires in 1 minute."

        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        # Try port 587 (STARTTLS) first — more reliable on PythonAnywhere
        sent = False
        try:
            with smtplib.SMTP('smtp.gmail.com', 587, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
                server.send_message(msg)
            sent = True
        except Exception as e587:
            print(f'SMTP 587 failed: {e587}')

        if not sent:
            try:
                with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=15) as server:
                    server.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
                    server.send_message(msg)
                sent = True
            except Exception as e465:
                print(f'SMTP 465 also failed: {e465}')

        return sent
    except Exception as e:
        print(f'Email send FAILED: {e}')
        return False


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            full_name TEXT DEFAULT '',
            country TEXT DEFAULT '',
            field_of_study TEXT DEFAULT '',
            education_level TEXT DEFAULT '',
            gpa TEXT DEFAULT '',
            interests TEXT DEFAULT '',
            bio TEXT DEFAULT '',
            is_admin INTEGER DEFAULT 0,
            email_verified INTEGER DEFAULT 0,
            verification_code TEXT DEFAULT '',
            verification_expires DATETIME DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_type TEXT NOT NULL,
            item_name TEXT NOT NULL,
            item_data TEXT DEFAULT '{}',
            notes TEXT DEFAULT '',
            status TEXT DEFAULT 'interested',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, item_type, item_name)
        );

        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS search_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            query TEXT NOT NULL,
            results_count INTEGER DEFAULT 0,
            category TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Migrate existing tables — add new columns if missing
    cursor = db.execute("PRAGMA table_info(users)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    if 'email_verified' not in existing_cols:
        db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 1")  # Existing users are auto-verified
    if 'verification_code' not in existing_cols:
        db.execute("ALTER TABLE users ADD COLUMN verification_code TEXT DEFAULT ''")
    if 'verification_expires' not in existing_cols:
        db.execute("ALTER TABLE users ADD COLUMN verification_expires DATETIME DEFAULT NULL")

    db.commit()
    db.close()

# ============================================
# AUTH HELPERS
# ============================================
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return hashed.hex(), salt

def verify_password(password, password_hash, salt):
    hashed, _ = hash_password(password, salt)
    return hashed == password_hash

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Login required'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Login required'}), 401
        db = get_db()
        user = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user or not user['is_admin']:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user_id' not in session:
        return None
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

def log_activity(user_id, action, details=''):
    try:
        db = get_db()
        ip = request.remote_addr or ''
        db.execute(
            'INSERT INTO activity_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
            (user_id, action, details, ip)
        )
        db.commit()
    except Exception:
        pass

# ============================================
# LOAD DATA FILES
# ============================================
# ============================================
# CACHING LAYER — keeps JSON data in memory
# ============================================
_json_cache = {}       # filename -> data
_json_cache_mtime = {} # filename -> last modified time

def load_json(filename):
    """Load JSON with automatic file-change detection cache.
    Re-reads only when the file has been modified (mtime changed).
    Zero-TTL — always fresh, but avoids re-parsing unchanged files."""
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return []
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = 0

    # Return cached version if file hasn't changed
    if filename in _json_cache and _json_cache_mtime.get(filename) == mtime:
        return _json_cache[filename]

    # File changed (or first load) — read and cache
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    _json_cache[filename] = data
    _json_cache_mtime[filename] = mtime
    return data

def clear_json_cache(filename=None):
    """Clear cache for a specific file or all files."""
    if filename:
        _json_cache.pop(filename, None)
        _json_cache_mtime.pop(filename, None)
    else:
        _json_cache.clear()
        _json_cache_mtime.clear()

def get_scholarships():
    return load_json('scholarships.json')

def get_universities():
    return load_json('universities.json')

def get_opportunities():
    return load_json('opportunities.json')

def get_cost_of_living():
    return load_json('cost_data.json')

def get_visa_guides():
    return load_json('visa_data.json')

def get_faq():
    return load_json('faq_data.json')

def get_test_prep():
    return load_json('test_prep_data.json')

def get_essay_guides():
    return load_json('essay_guides.json')

# ============================================
# SCHOLARSHIP MATCHING
# ============================================
def match_scholarships(user):
    """Match scholarships to user profile — returns sorted by relevance"""
    scholarships = get_scholarships()
    if not user:
        return scholarships

    scored = []
    user_country = (user['country'] or '').lower()
    user_field = (user['field_of_study'] or '').lower()
    user_level = (user['education_level'] or '').lower()
    user_interests = (user['interests'] or '').lower()

    for s in scholarships:
        score = 0
        s_str = json.dumps(s).lower()

        # Country match
        if user_country and user_country in s_str:
            score += 30

        # Field match
        if user_field:
            fields = [f.strip() for f in user_field.split(',')]
            for field in fields:
                if field and field in s_str:
                    score += 25
                    break

        # Education level match
        if user_level:
            level_map = {
                'undergraduate': ['undergraduate', 'bachelor', 'bsc', 'ba'],
                'masters': ['masters', 'master', 'msc', 'ma', 'graduate'],
                'phd': ['phd', 'doctoral', 'doctorate', 'research'],
            }
            for key, terms in level_map.items():
                if key in user_level:
                    for term in terms:
                        if term in s_str:
                            score += 20
                            break
                    break

        # Interest match
        if user_interests:
            interests = [i.strip() for i in user_interests.split(',')]
            for interest in interests:
                if interest and interest in s_str:
                    score += 10

        # Fully funded bonus
        if 'full' in s_str and ('tuition' in s_str or 'funded' in s_str):
            score += 5

        scored.append((score, s))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [s for _, s in scored]


# ============================================
# CSRF PROTECTION
# ============================================
# Clean up stale unverified accounts (older than 1 hour)
@app.before_request
def cleanup_unverified():
    if request.endpoint and request.endpoint in ('static', 'serve_upload'):
        return  # Skip for static files
    try:
        db = get_db()
        db.execute(
            "DELETE FROM users WHERE email_verified = 0 AND created_at < datetime('now', '-1 hour')"
        )
        db.commit()
    except Exception:
        pass

@app.before_request
def csrf_protect():
    if request.method == 'POST' and not request.path.startswith('/api/'):
        token = session.get('csrf_token')
        form_token = request.form.get('csrf_token')
        if not token or token != form_token:
            # Skip CSRF for API, webhook, and JSON requests (verify uses AJAX)
            if not request.is_json and not request.path.startswith('/webhook') and not request.path.startswith('/verify'):
                flash('Session expired. Please try again.', 'error')
                return redirect(request.url)

@app.before_request
def generate_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

@app.context_processor
def inject_tracking():
    return {"ga_id": GOOGLE_ANALYTICS_ID, "adsense_id": ADSENSE_ID}

@app.context_processor
def inject_csrf():
    return dict(csrf_token=session.get('csrf_token', ''))

# ============================================
# PAGE ROUTES
# ============================================
@app.route('/')
def index():
    user = get_current_user()
    stats = {
        'scholarships': len(get_scholarships()),
        'universities': len(get_universities()),
        'opportunities': len(get_opportunities()),
        'cities': len(get_cost_of_living()),
        'visa_countries': len(get_visa_guides()),
    }
    # Last updated timestamp from scholarships data file
    try:
        schol_path = os.path.join(DATA_DIR, 'scholarships.json')
        mtime = os.path.getmtime(schol_path)
        last_updated = datetime.fromtimestamp(mtime).strftime('%B %d, %Y')
    except Exception:
        last_updated = None
    return render_template('index.html', user=user, stats=stats, last_updated=last_updated)

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        full_name = request.form.get('full_name', '').strip()

        if not email or not username or not password:
            flash('All fields are required', 'error')
            return render_template('signup.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('signup.html')

        if len(username) < 3:
            flash('Username must be at least 3 characters', 'error')
            return render_template('signup.html')

        db = get_db()
        existing = db.execute(
            'SELECT id FROM users WHERE email = ? OR username = ?',
            (email, username)
        ).fetchone()

        if existing:
            flash('Email or username already taken', 'error')
            return render_template('signup.html')

        country = request.form.get('country', '').strip()
        education_level = request.form.get('education_level', '').strip()
        field_of_study = request.form.get('field_of_study', '').strip()

        if not request.form.get('terms'):
            flash('You must agree to the Terms & Conditions', 'error')
            return render_template('signup.html')

        dob_day = request.form.get('dob_day', '')
        dob_month = request.form.get('dob_month', '')
        dob_year = request.form.get('dob_year', '')
        dob = f"{dob_day}/{dob_month}/{dob_year}" if dob_day and dob_month and dob_year else ''
        hear_about = request.form.get('hear_about', '').strip()
        friend_name = request.form.get('friend_name', '').strip()

        password_hash, salt = hash_password(password)
        is_admin = 1 if email == ADMIN_EMAIL else 0

        # Generate verification code
        code = generate_verification_code()
        expires = (datetime.now() + timedelta(minutes=VERIFICATION_EXPIRY_MINUTES)).strftime('%Y-%m-%d %H:%M:%S')

        # Send verification email FIRST — don't create account if email fails
        sent = send_verification_email(email, code, full_name)
        if not sent:
            flash('Could not send verification email. Please check your email address and try again.', 'error')
            return render_template('signup.html')

        db.execute(
            'INSERT INTO users (email, username, password_hash, salt, full_name, is_admin, country, education_level, field_of_study, dob, hear_about, friend_name, email_verified, verification_code, verification_expires) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)',
            (email, username, password_hash, salt, full_name, is_admin, country, education_level, field_of_study, dob, hear_about, friend_name, code, expires)
        )
        db.commit()

        user = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        log_activity(user['id'], 'signup')

        # Handle avatar upload during signup
        if 'avatar' in request.files:
            f = request.files['avatar']
            if f.filename:
                ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else 'jpg'
                if ext in ('jpg', 'jpeg', 'png', 'gif', 'webp'):
                    fname = f"avatar_{user['id']}.{ext}"
                    upload_dir = os.path.join(os.path.dirname(__file__), 'uploads', 'avatars')
                    os.makedirs(upload_dir, exist_ok=True)
                    f.save(os.path.join(upload_dir, fname))
                    db.execute('UPDATE users SET avatar = ? WHERE id = ?', (f"/uploads/avatars/{fname}", user['id']))
                    db.commit()

        # Store email in session for verification page (don't log them in yet)
        session['pending_verification_email'] = email
        return redirect(url_for('verify_page'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        login_id = request.form.get('login_id', '').strip().lower()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE email = ? OR username = ?',
            (login_id, login_id)
        ).fetchone()

        # Rate limiting
        client_ip = request.remote_addr or 'unknown'
        if not check_rate_limit(client_ip):
            flash('Too many login attempts. Please wait 5 minutes.', 'error')
            return render_template('login.html')

        if not user or not verify_password(password, user['password_hash'], user['salt']):
            flash('Invalid email/username or password', 'error')
            return render_template('login.html')

        # Check if email is verified
        if not user['email_verified']:
            # Resend a fresh code
            code = generate_verification_code()
            expires = (datetime.now() + timedelta(minutes=VERIFICATION_EXPIRY_MINUTES)).strftime('%Y-%m-%d %H:%M:%S')
            db.execute('UPDATE users SET verification_code = ?, verification_expires = ? WHERE id = ?',
                       (code, expires, user['id']))
            db.commit()
            send_verification_email(user['email'], code, user['full_name'])
            session['pending_verification_email'] = user['email']
            flash('Please verify your email first. A new code has been sent.', 'error')
            return redirect(url_for('verify_page'))

        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
        db.commit()
        log_activity(user['id'], 'login')

        return redirect(url_for('dashboard_page'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    log_activity(session.get('user_id'), 'logout')
    session.clear()
    return redirect(url_for('index'))

@app.route('/verify', methods=['GET', 'POST'])
def verify_page():
    email = session.get('pending_verification_email')
    if not email:
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        # Accept code from either form field or JSON
        if request.is_json:
            code = request.get_json().get('code', '').strip()
        else:
            # Combine OTP digits from individual inputs
            digits = []
            for i in range(1, 7):
                d = request.form.get(f'digit{i}', '')
                digits.append(d)
            code = ''.join(digits).strip()

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if not user:
            flash('Account not found.', 'error')
            return redirect(url_for('signup_page'))

        # Check expiry
        if user['verification_expires']:
            try:
                expires = datetime.strptime(user['verification_expires'], '%Y-%m-%d %H:%M:%S')
                if datetime.now() > expires:
                    if request.is_json:
                        return jsonify({'error': 'Code expired. Please request a new one.'}), 400
                    flash('Code expired. Please request a new one.', 'error')
                    return render_template('verify.html', email=email)
            except Exception:
                pass

        if user['verification_code'] != code:
            if request.is_json:
                return jsonify({'error': 'Incorrect code. Please try again.'}), 400
            flash('Incorrect code. Please try again.', 'error')
            return render_template('verify.html', email=email)

        # Verified!
        db.execute('UPDATE users SET email_verified = 1, verification_code = NULL, verification_expires = NULL WHERE id = ?',
                   (user['id'],))
        db.commit()
        log_activity(user['id'], 'email_verified')

        # Log them in
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session.pop('pending_verification_email', None)
        db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
        db.commit()

        if request.is_json:
            return jsonify({'success': True, 'redirect': url_for('dashboard_page') + '?welcome=1'})
        return redirect(url_for('dashboard_page') + '?welcome=1')

    return render_template('verify.html', email=email)

@app.route('/verify/resend', methods=['POST'])
def resend_verification():
    email = session.get('pending_verification_email')
    if not email:
        return jsonify({'error': 'No pending verification'}), 400

    if not check_resend_limit(email):
        return jsonify({'error': 'Too many resend attempts. Please wait 5 minutes.'}), 429

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if not user:
        return jsonify({'error': 'Account not found'}), 404

    if user['email_verified']:
        return jsonify({'error': 'Email already verified'}), 400

    code = generate_verification_code()
    expires = (datetime.now() + timedelta(minutes=VERIFICATION_EXPIRY_MINUTES)).strftime('%Y-%m-%d %H:%M:%S')
    db.execute('UPDATE users SET verification_code = ?, verification_expires = ? WHERE id = ?',
               (code, expires, user['id']))
    db.commit()

    sent = send_verification_email(email, code, user['full_name'])
    if sent:
        return jsonify({'success': True, 'message': 'New code sent!'})
    else:
        return jsonify({'error': 'Failed to send email. Please try again.'}), 500

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile_page():
    db = get_db()
    user = get_current_user()

    if request.method == 'POST':
        db.execute("""
            UPDATE users SET
                full_name = ?, country = ?, field_of_study = ?,
                education_level = ?, gpa = ?, interests = ?, bio = ?
            WHERE id = ?
        """, (
            request.form.get('full_name', ''),
            request.form.get('country', ''),
            request.form.get('field_of_study', ''),
            request.form.get('education_level', ''),
            request.form.get('gpa', ''),
            request.form.get('interests', ''),
            request.form.get('bio', ''),
            session['user_id']
        ))
        db.commit()
        log_activity(session['user_id'], 'profile_update')
        flash('Profile updated!', 'success')
        return redirect(url_for('dashboard_page'))

    return render_template('profile.html', user=user)

@app.route('/upload-avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('profile_page'))
    f = request.files['avatar']
    if f.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('profile_page'))
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else 'jpg'
    if ext not in ('jpg', 'jpeg', 'png', 'gif', 'webp'):
        flash('Only image files allowed', 'error')
        return redirect(url_for('profile_page'))
    fname = f"avatar_{session['user_id']}.{ext}"
    upload_dir = os.path.join(os.path.dirname(__file__), 'uploads', 'avatars')
    os.makedirs(upload_dir, exist_ok=True)
    f.save(os.path.join(upload_dir, fname))
    db = get_db()
    db.execute('UPDATE users SET avatar = ? WHERE id = ?', (f"/uploads/avatars/{fname}", session['user_id']))
    db.commit()
    flash('Profile picture updated!', 'success')
    return redirect(url_for('profile_page'))

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(os.path.join(os.path.dirname(__file__), 'uploads'), filename)

@app.route('/upload-resume', methods=['POST'])
@login_required
def upload_resume():
    if 'resume' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f = request.files['resume']
    if f.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else 'pdf'
    if ext not in ('pdf', 'doc', 'docx', 'txt'):
        return jsonify({'error': 'Only PDF, DOC, DOCX, TXT allowed'}), 400
    fname = f"resume_{session['user_id']}.{ext}"
    upload_dir = os.path.join(os.path.dirname(__file__), 'uploads', 'resumes')
    os.makedirs(upload_dir, exist_ok=True)
    f.save(os.path.join(upload_dir, fname))
    # Read text for analysis
    content = ''
    fpath = os.path.join(upload_dir, fname)
    if ext == 'txt':
        with open(fpath, 'r', errors='ignore') as rf: content = rf.read()
    elif ext == 'pdf':
        try:
            import subprocess
            result = subprocess.run(['pdftotext', fpath, '-'], capture_output=True, text=True, timeout=10)
            content = result.stdout
        except: content = '[PDF uploaded — text extraction not available]'
    else:
        content = '[Document uploaded — please paste text for detailed analysis]'
    return jsonify({'success': True, 'text': content, 'filename': fname})

@app.route('/api/admin/send-email', methods=['POST'])
@admin_required
def api_admin_send_email():
    data = request.get_json()
    to_emails = data.get('to', [])
    subject = data.get('subject', '')
    body = data.get('body', '')
    if not to_emails or not subject or not body:
        return jsonify({'error': 'Missing to, subject, or body'}), 400
    # Store emails in DB for now (actual SMTP can be configured later)
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS sent_emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        to_email TEXT, subject TEXT, body TEXT, sent_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    sent = 0
    for email in to_emails:
        db.execute('INSERT INTO sent_emails (to_email, subject, body) VALUES (?, ?, ?)', (email, subject, body))
        sent += 1
    db.commit()
    return jsonify({'success': True, 'sent': sent, 'note': 'Emails queued. Configure SMTP in settings to actually deliver.'})

@app.route('/api/admin/users-full')
@admin_required
def api_admin_users_full():
    db = get_db()
    users = db.execute('''
        SELECT u.*, COUNT(b.id) as bookmark_count
        FROM users u LEFT JOIN bookmarks b ON u.id = b.user_id
        GROUP BY u.id ORDER BY u.created_at DESC
    ''').fetchall()
    return jsonify([dict(u) for u in users])

@app.route('/dashboard')
@login_required
def dashboard_page():
    user = get_current_user()
    db = get_db()

    bookmarks = db.execute(
        'SELECT * FROM bookmarks WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()

    matched = match_scholarships(user)[:10]

    # Collect deadlines from user's SAVED scholarships only
    deadlines = []
    all_scholarships = get_scholarships()
    saved_names = {b['item_name'].lower() for b in bookmarks if b['item_type'] == 'scholarship'}
    for s in all_scholarships:
        name = s.get('name', s.get('title', ''))
        if name.lower() in saved_names:
            dl = s.get('deadline', '')
            if dl and dl.lower() not in ('varies', 'rolling', 'varies by university', 'ongoing', 'n/a', ''):
                deadlines.append({
                    'name': name,
                    'deadline': dl,
                    'country': s.get('country', ''),
                    'link': s.get('link', s.get('url', '')),
                })

    stats = {
        'bookmarks': len(bookmarks),
        'deadlines': len(deadlines),
    }

    return render_template('dashboard.html', user=user, bookmarks=bookmarks, matched=matched, stats=stats, deadlines=deadlines)

@app.route('/scholarships')
def scholarships_page():
    user = get_current_user()
    return render_template('scholarships.html', user=user)

@app.route('/universities')
def universities_page():
    user = get_current_user()
    return render_template('universities.html', user=user)

@app.route('/opportunities')
def opportunities_page():
    user = get_current_user()
    return render_template('opportunities.html', user=user)

@app.route('/cost-of-living')
def cost_page():
    user = get_current_user()
    return render_template('cost.html', user=user, costs=get_cost_of_living())

@app.route('/visa-guide')
def visa_page():
    user = get_current_user()
    return render_template('visa.html', user=user, visas=get_visa_guides())

@app.route('/test-prep')
def testprep_page():
    user = get_current_user()
    return render_template('testprep.html', user=user)

@app.route('/faq')
def faq_page():
    user = get_current_user()
    return render_template('faq.html', user=user)

# ============================================
# API ENDPOINTS
# ============================================
@app.route('/api/scholarships')
def api_scholarships():
    q = request.args.get('q', '').lower()
    level = request.args.get('level', '').lower()
    country = request.args.get('country', '').lower()
    field = request.args.get('field', '').lower()
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))

    user = get_current_user()
    if user:
        scholarships = match_scholarships(user)
    else:
        scholarships = get_scholarships()

    # Filter
    results = []
    for s in scholarships:
        s_str = json.dumps(s).lower()
        if q and q not in s_str:
            continue
        if level and level not in s_str:
            continue
        if country and country not in s_str:
            continue
        if field and field not in s_str:
            continue
        results.append(s)

    # Log search
    if q and session.get('user_id'):
        try:
            db = get_db()
            db.execute(
                'INSERT INTO search_log (user_id, query, results_count, category) VALUES (?, ?, ?, ?)',
                (session['user_id'], q, len(results), 'scholarships')
            )
            db.commit()
        except Exception:
            pass

    total = len(results)
    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'total': total,
        'page': page,
        'per_page': per_page,
        'results': results[start:end]
    })

@app.route('/api/universities')
def api_universities():
    q = request.args.get('q', '').lower()
    country = request.args.get('country', '').lower()
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))

    universities = get_universities()
    results = []
    for u in universities:
        u_str = json.dumps(u).lower()
        if q and q not in u_str:
            continue
        if country and country not in u_str:
            continue
        results.append(u)

    total = len(results)
    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'total': total,
        'page': page,
        'per_page': per_page,
        'results': results[start:end]
    })

@app.route('/api/opportunities')
def api_opportunities():
    q = request.args.get('q', '').lower()
    otype = request.args.get('type', '').lower()
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))

    opportunities = get_opportunities()
    results = []
    for o in opportunities:
        o_str = json.dumps(o).lower()
        if q and q not in o_str:
            continue
        if otype and otype not in o_str:
            continue
        results.append(o)

    total = len(results)
    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'total': total,
        'page': page,
        'per_page': per_page,
        'results': results[start:end]
    })

@app.route('/api/cost')
def api_cost():
    return jsonify(get_cost_of_living())

@app.route('/api/visa')
def api_visa():
    return jsonify(get_visa_guides())

@app.route('/api/faq')
def api_faq():
    return jsonify(get_faq())

@app.route('/api/testprep')
def api_testprep():
    return jsonify(get_test_prep())

@app.route('/api/essays')
def api_essays():
    return jsonify(get_essay_guides())

@app.route('/api/stats')
def api_stats():
    return jsonify({
        'scholarships': len(get_scholarships()),
        'universities': len(get_universities()),
        'opportunities': len(get_opportunities()),
        'cities': len(get_cost_of_living()),
        'visa_countries': len(get_visa_guides()),
        'faq': len(get_faq()),
    })

# ============================================
# BOOKMARK API
# ============================================
@app.route('/api/bookmarks', methods=['GET'])
@login_required
def api_get_bookmarks():
    db = get_db()
    bookmarks = db.execute(
        'SELECT * FROM bookmarks WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    return jsonify([dict(b) for b in bookmarks])

@app.route('/api/bookmarks', methods=['POST'])
@login_required
def api_add_bookmark():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    item_type = data.get('type', '')
    item_name = data.get('name', '')

    if not item_type or not item_name:
        return jsonify({'error': 'Type and name required'}), 400

    db = get_db()
    try:
        db.execute(
            'INSERT INTO bookmarks (user_id, item_type, item_name, item_data) VALUES (?, ?, ?, ?)',
            (session['user_id'], item_type, item_name, json.dumps(data.get('data', {})))
        )
        db.commit()
        log_activity(session['user_id'], 'bookmark_add', f'{item_type}: {item_name}')
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Already bookmarked'}), 409

@app.route('/api/bookmarks/<int:bookmark_id>', methods=['DELETE'])
@login_required
def api_remove_bookmark(bookmark_id):
    db = get_db()
    db.execute(
        'DELETE FROM bookmarks WHERE id = ? AND user_id = ?',
        (bookmark_id, session['user_id'])
    )
    db.commit()
    return jsonify({'success': True})

@app.route('/api/bookmarks/<int:bookmark_id>/status', methods=['PUT'])
@login_required
def api_update_bookmark_status(bookmark_id):
    data = request.get_json()
    status = data.get('status', 'interested')
    db = get_db()
    db.execute(
        'UPDATE bookmarks SET status = ? WHERE id = ? AND user_id = ?',
        (status, bookmark_id, session['user_id'])
    )
    db.commit()
    return jsonify({'success': True})

# ============================================
# MATCHING API
# ============================================
@app.route('/api/match')
@login_required
def api_match():
    user = get_current_user()
    matched = match_scholarships(user)
    limit = int(request.args.get('limit', 20))
    return jsonify({
        'total': len(matched),
        'results': matched[:limit]
    })

# ============================================
# ADMIN API
# ============================================
@app.route('/api/admin/stats')
@admin_required
def api_admin_stats():
    db = get_db()
    total_users = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    total_bookmarks = db.execute('SELECT COUNT(*) FROM bookmarks').fetchone()[0]
    total_searches = db.execute('SELECT COUNT(*) FROM search_log').fetchone()[0]

    recent_users = db.execute(
        'SELECT username, email, country, created_at FROM users ORDER BY created_at DESC LIMIT 20'
    ).fetchall()

    top_searches = db.execute(
        'SELECT query, COUNT(*) as cnt FROM search_log GROUP BY query ORDER BY cnt DESC LIMIT 20'
    ).fetchall()

    daily_signups = db.execute(
        "SELECT date(created_at) as day, COUNT(*) as cnt FROM users GROUP BY day ORDER BY day DESC LIMIT 30"
    ).fetchall()

    return jsonify({
        'total_users': total_users,
        'total_bookmarks': total_bookmarks,
        'total_searches': total_searches,
        'recent_users': [dict(u) for u in recent_users],
        'top_searches': [dict(s) for s in top_searches],
        'daily_signups': [dict(d) for d in daily_signups],
    })

@app.route('/admin')
@login_required
def admin_page():
    user = get_current_user()
    if not user['is_admin']:
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard_page'))
    stats = {
        'scholarships': len(get_scholarships()),
        'opportunities': len(get_opportunities()),
    }
    return render_template('admin.html', user=user, stats=stats)

@app.route('/api/admin/delete-user', methods=['POST'])
@admin_required
def api_admin_delete_user():
    data = request.get_json()
    username = data.get('username')
    if not username:
        return jsonify({'error': 'No username provided'}), 400
    db = get_db()
    user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    db.execute('DELETE FROM bookmarks WHERE user_id = ?', (user['id'],))
    db.execute('DELETE FROM search_log WHERE user_id = ?', (user['id'],))
    db.execute('DELETE FROM users WHERE id = ?', (user['id'],))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/admin/clear-searches', methods=['POST'])
@admin_required
def api_admin_clear_searches():
    db = get_db()
    db.execute('DELETE FROM search_log')
    db.commit()
    return jsonify({'success': True, 'message': 'Search logs cleared'})

# ============================================
# TOOLS — Essay Rater, School Matcher, Resume Review
# ============================================
@app.route('/agents/<agent_type>')
def agent_page(agent_type):
    agents = {
        'scout': 'Scout — Scholarship Finder',
        'writer': 'Writer — Essay Assistant',
        'profiler': 'Profiler — Student Matcher',
        'tracker': 'Tracker — Deadline Manager',
        'advisor': 'Advisor — Strategy Coach',
        'prep': 'Prep — Interview Coach',
    }
    if agent_type not in agents:
        return render_template('404.html'), 404
    user = get_current_user()
    return render_template('agent.html', user=user, agent_key=agent_type, agent_title=agents[agent_type])

@app.route('/tools/essay-rater', methods=['GET'])
def essay_rater_page():
    user = get_current_user()
    return render_template('tool_essay.html', user=user)

@app.route('/api/tools/rate-essay', methods=['POST'])
def api_rate_essay():
    data = request.get_json()
    essay = data.get('essay', '').strip()
    essay_type = data.get('type', 'personal_statement')
    if not essay:
        return jsonify({'error': 'No essay provided'}), 400

    words = essay.split()
    word_count = len(words)
    sentences = [s.strip() for s in essay.replace('!', '.').replace('?', '.').split('.') if s.strip()]
    sentence_count = len(sentences)
    paragraphs = [p.strip() for p in essay.split('\n\n') if p.strip()]

    type_labels = {
        'personal_statement': 'Personal Statement',
        'sop': 'Statement of Purpose',
        'motivation': 'Motivation Letter',
        'other': 'Essay'
    }
    type_label = type_labels.get(essay_type, 'Essay')

    # AI-powered analysis via Groq
    system_prompt = f"""You are an elite admissions consultant who has reviewed thousands of scholarship and university application essays. You provide brutally honest, professional feedback.

Analyze this {type_label} and return ONLY valid JSON (no markdown, no code blocks) in this exact format:
{{
    "score": <integer 1-10>,
    "label": "<rating label>",
    "feedback": [
        ["<emoji>", "<feedback point>"],
        ["<emoji>", "<feedback point>"]
    ],
    "summary": "<2-3 sentence overall assessment>"
}}

SCORING GUIDE (be strict — most essays are 4-6):
- 10: Publication-worthy. Exceptional in every way. Almost never given.
- 9: Outstanding. Compelling narrative, flawless execution, memorable.
- 8: Very strong. Clear voice, great structure, minor improvements possible.
- 7: Good. Solid essay with some areas to polish.
- 6: Above average. Shows promise but has noticeable weaknesses.
- 5: Average. Gets the job done but won't stand out.
- 4: Below average. Missing key elements or poorly executed.
- 3: Weak. Major structural or content issues.
- 2: Very weak. Barely addresses the purpose.
- 1: Incomplete or incoherent.

FEEDBACK RULES:
- Give 5-8 specific feedback points
- Use these emojis: ✅ (strength), ❌ (critical issue), ⚠️ (needs improvement), 💡 (suggestion)
- Be specific — reference actual lines/phrases from the essay
- Include at least 2 strengths and 2 areas for improvement
- Comment on: opening hook, narrative arc, personal voice, specificity, conclusion, word choice, clichés, impact

Word count: {word_count} | Paragraphs: {len(paragraphs)} | Type: {type_label}"""

    try:
        ai_payload = json.dumps({
            'model': GROQ_MODEL,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': essay}
            ],
            'max_tokens': 1500,
            'temperature': 0.3
        }).encode('utf-8')

        result = call_groq(ai_payload)
        ai_text = result['choices'][0]['message']['content'].strip()

        # Clean markdown code blocks if present
        if ai_text.startswith('```'):
            ai_text = ai_text.split('\n', 1)[1] if '\n' in ai_text else ai_text[3:]
        if ai_text.endswith('```'):
            ai_text = ai_text[:-3]
        ai_text = ai_text.strip()

        ai_data = json.loads(ai_text)

        # Ensure score is in range
        score = max(1, min(10, int(ai_data.get('score', 5))))

        return jsonify({
            'score': score,
            'label': ai_data.get('label', 'Reviewed'),
            'word_count': word_count,
            'sentence_count': sentence_count,
            'paragraph_count': len(paragraphs),
            'feedback': ai_data.get('feedback', []),
            'summary': ai_data.get('summary', ''),
            'ai_powered': True
        })

    except Exception as e:
        import traceback; print(f'Essay AI analysis failed: {e}'); traceback.print_exc()
        # Fallback to basic analysis
        score = 5
        feedback = [
            ['⚠️', f'Word count: {word_count} words, {sentence_count} sentences, {len(paragraphs)} paragraph(s)'],
            ['💡', 'AI analysis temporarily unavailable — showing basic metrics only. Please try again.']
        ]
        return jsonify({
            'score': score,
            'label': 'Basic Analysis',
            'word_count': word_count,
            'sentence_count': sentence_count,
            'paragraph_count': len(paragraphs),
            'feedback': feedback,
            'ai_powered': False,
            'field_warning': field_warning if field_warning else None
        })


@app.route('/tools/school-matcher', methods=['GET'])
def school_matcher_page():
    user = get_current_user()
    return render_template('tool_school.html', user=user)

@app.route('/api/tools/match-schools', methods=['POST'])
def api_match_schools():
    data = request.get_json()
    gpa = data.get('gpa', '').strip()
    country_pref = data.get('country', '').lower()
    field = data.get('field', '').lower()
    budget = data.get('budget', '').lower()

    universities = get_universities()
    results = []

    for u in universities:
        u_str = json.dumps(u).lower()
        score = 0

        # Country match
        if country_pref and country_pref in u_str:
            score += 30

        # Field match
        if field and field in u_str:
            score += 25

        # Budget consideration
        tuition = u_str
        if budget == 'low' and ('free' in tuition or 'low' in tuition or 'no tuition' in tuition):
            score += 20
        elif budget == 'medium' and ('moderate' in tuition or 'medium' in tuition):
            score += 15

        # Ranking-based GPA matching
        ranking = u.get('ranking', 999)
        try:
            rank_num = int(str(ranking).replace('#', '').replace('+', '').split('-')[0])
        except (ValueError, TypeError):
            rank_num = 500

        # GPA matching logic
        try:
            gpa_val = float(gpa.split('/')[0]) if '/' in gpa else float(gpa)
            gpa_scale = float(gpa.split('/')[1]) if '/' in gpa else 4.0
            gpa_pct = gpa_val / gpa_scale
        except (ValueError, TypeError):
            gpa_pct = 0.75  # default

        if gpa_pct >= 0.9 and rank_num <= 50: score += 20
        elif gpa_pct >= 0.8 and rank_num <= 100: score += 20
        elif gpa_pct >= 0.7 and rank_num <= 200: score += 20
        elif gpa_pct >= 0.6: score += 10

        if score > 0:
            chance = 'High' if gpa_pct >= 0.85 and rank_num > 100 else 'Medium' if gpa_pct >= 0.7 else 'Reach'
            if rank_num <= 20: chance = 'Reach' if gpa_pct < 0.95 else 'Medium'
            results.append({**u, 'match_score': score, 'chance': chance})

    results.sort(key=lambda x: x['match_score'], reverse=True)
    return jsonify({'results': results[:15]})

@app.route('/tools/resume-review', methods=['GET'])
def resume_review_page():
    user = get_current_user()
    return render_template('tool_resume.html', user=user)

@app.route('/api/tools/rate-resume', methods=['POST'])
def api_rate_resume():
    resume = ''

    # Handle file upload (FormData)
    if 'file' in request.files:
        f = request.files['file']
        if f.filename:
            ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
            if ext == 'txt':
                resume = f.read().decode('utf-8', errors='ignore')
            elif ext == 'pdf':
                import tempfile, subprocess
                with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp:
                    f.save(tmp.name)
                    try:
                        result = subprocess.run(['pdftotext', tmp.name, '-'], capture_output=True, text=True, timeout=10)
                        resume = result.stdout
                    except Exception:
                        resume = ''
                    import os as _os
                    _os.unlink(tmp.name)
            else:
                resume = f.read().decode('utf-8', errors='ignore')

    # Handle JSON body (pasted text)
    if not resume:
        data = request.get_json(silent=True) or {}
        resume = data.get('resume', '').strip()

    if not resume:
        return jsonify({'error': 'No resume provided'}), 400

    words = resume.split()
    word_count = len(words)
    resume_lower = resume.lower()

    # Detect sections for display
    sections_map = {
        'education': ['education', 'university', 'school', 'degree', 'gpa', 'major'],
        'experience': ['experience', 'work', 'intern', 'job', 'position', 'role'],
        'skills': ['skills', 'proficient', 'languages', 'tools', 'technologies', 'programming'],
        'projects': ['project', 'built', 'developed', 'created', 'designed'],
        'activities': ['activities', 'extracurricular', 'volunteer', 'leadership', 'club']
    }
    sections_found = [s for s, kw in sections_map.items() if any(k in resume_lower for k in kw)]

    # AI-powered analysis via Groq
    system_prompt = f"""You are a top-tier career coach and resume expert who has reviewed resumes for Fortune 500 companies, top universities, and competitive scholarship programs. You provide sharp, actionable feedback.

Analyze this resume and return ONLY valid JSON (no markdown, no code blocks) in this exact format:
{{
    "score": <integer 1-10>,
    "label": "<rating label>",
    "feedback": [
        ["<emoji>", "<feedback point>"],
        ["<emoji>", "<feedback point>"]
    ],
    "summary": "<2-3 sentence overall assessment>"
}}

SCORING GUIDE (be strict — most resumes are 4-6):
- 10: Flawless. Would impress any recruiter instantly. Almost never given.
- 9: Outstanding. Strong achievements, perfect structure, compelling throughout.
- 8: Very strong. Well-crafted with minor tweaks needed.
- 7: Good. Solid resume with some areas to strengthen.
- 6: Above average. Decent but won't stand out in competitive pools.
- 5: Average. Has the basics but lacks impact.
- 4: Below average. Missing key sections or weak descriptions.
- 3: Weak. Major gaps in content or structure.
- 2: Very weak. Barely functional as a resume.
- 1: Not a resume or completely incoherent.

FEEDBACK RULES:
- Give 6-10 specific, actionable feedback points
- Use these emojis: ✅ (strength), ❌ (critical issue), ⚠️ (needs improvement), 💡 (pro tip)
- Be specific — reference actual content from the resume
- Include at least 2 strengths and 2 improvements
- Evaluate: structure/layout, action verbs, quantified achievements, relevance, keywords, contact info, section completeness, readability, ATS-friendliness
- If achievements lack numbers, suggest specific ways to quantify them
- Note any red flags (gaps, vague descriptions, missing sections)

Word count: {word_count} | Sections detected: {', '.join(sections_found) if sections_found else 'unclear'}"""

    try:
        ai_payload = json.dumps({
            'model': GROQ_MODEL,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': resume}
            ],
            'max_tokens': 1500,
            'temperature': 0.3
        }).encode('utf-8')

        result = call_groq(ai_payload)
        ai_text = result['choices'][0]['message']['content'].strip()

        # Clean markdown code blocks if present
        if ai_text.startswith('```'):
            ai_text = ai_text.split('\n', 1)[1] if '\n' in ai_text else ai_text[3:]
        if ai_text.endswith('```'):
            ai_text = ai_text[:-3]
        ai_text = ai_text.strip()

        ai_data = json.loads(ai_text)

        score = max(1, min(10, int(ai_data.get('score', 5))))

        return jsonify({
            'score': score,
            'label': ai_data.get('label', 'Reviewed'),
            'word_count': word_count,
            'sections_found': sections_found,
            'feedback': ai_data.get('feedback', []),
            'summary': ai_data.get('summary', ''),
            'ai_powered': True
        })

    except Exception as e:
        import traceback; print(f'Resume AI analysis failed: {e}'); traceback.print_exc()
        # Fallback
        score = 5
        feedback = [
            ['⚠️', f'Detected sections: {", ".join(sections_found) if sections_found else "none"} ({word_count} words)'],
            ['💡', 'AI analysis temporarily unavailable — showing basic metrics only. Please try again.']
        ]
        return jsonify({
            'score': score,
            'label': 'Basic Analysis',
            'word_count': word_count,
            'sections_found': sections_found,
            'feedback': feedback,
            'ai_powered': False
        })


@app.route('/auth/google')
def google_auth():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Google login is not configured.', 'error')
        return redirect(url_for('signup_page'))

    # Generate state token for CSRF protection
    state = secrets.token_hex(16)
    session['google_oauth_state'] = state

    # Build the redirect URI
    redirect_uri = request.host_url.rstrip('/') + '/auth/google/callback'

    params = urllib.parse.urlencode({
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'access_type': 'offline',
        'prompt': 'select_account',
    })

    return redirect(f'{GOOGLE_AUTH_URL}?{params}')

@app.route('/auth/google/callback')
def google_callback():
    # Verify state
    if request.args.get('state') != session.pop('google_oauth_state', None):
        flash('Authentication failed — invalid state.', 'error')
        return redirect(url_for('login_page'))

    error = request.args.get('error')
    if error:
        flash(f'Google login cancelled.', 'error')
        return redirect(url_for('login_page'))

    code = request.args.get('code')
    if not code:
        flash('Authentication failed — no code received.', 'error')
        return redirect(url_for('login_page'))

    redirect_uri = request.host_url.rstrip('/') + '/auth/google/callback'

    # Exchange code for tokens
    try:
        token_data = urllib.parse.urlencode({
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
        }).encode('utf-8')

        token_req = urllib.request.Request(GOOGLE_TOKEN_URL, data=token_data, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        with urllib.request.urlopen(token_req, timeout=15) as resp:
            tokens = json.loads(resp.read().decode('utf-8'))

        access_token = tokens.get('access_token')
        if not access_token:
            flash('Authentication failed — no access token.', 'error')
            return redirect(url_for('login_page'))

    except Exception as e:
        print(f'Google token exchange error: {e}')
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('login_page'))

    # Get user info from Google
    try:
        info_req = urllib.request.Request(GOOGLE_USERINFO_URL, headers={
            'Authorization': f'Bearer {access_token}'
        })
        with urllib.request.urlopen(info_req, timeout=15) as resp:
            user_info = json.loads(resp.read().decode('utf-8'))

        google_email = user_info.get('email', '').lower()
        google_name = user_info.get('name', '')
        google_picture = user_info.get('picture', '')

        if not google_email:
            flash('Could not get email from Google.', 'error')
            return redirect(url_for('login_page'))

    except Exception as e:
        print(f'Google userinfo error: {e}')
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('login_page'))

    db = get_db()

    # Check if user already exists with this email
    user = db.execute('SELECT * FROM users WHERE email = ?', (google_email,)).fetchone()

    if user:
        # Existing user — log them in (auto-verify if not yet verified)
        if not user['email_verified']:
            db.execute('UPDATE users SET email_verified = 1, verification_code = NULL, verification_expires = NULL WHERE id = ?',
                       (user['id'],))

        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session.pop('pending_verification_email', None)
        db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
        db.commit()
        log_activity(user['id'], 'login_google')
        return redirect(url_for('dashboard_page'))

    else:
        # New user — create account (auto-verified, no password needed for Google-only)
        # Generate a username from email
        base_username = google_email.split('@')[0].lower()
        base_username = ''.join(c for c in base_username if c.isalnum() or c == '_')[:20]
        username = base_username

        # Handle username collisions
        counter = 1
        while db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            username = f'{base_username}{counter}'
            counter += 1

        # Generate a random password (user won't need it — they log in via Google)
        random_password = secrets.token_hex(16)
        password_hash, salt = hash_password(random_password)
        is_admin = 1 if google_email == ADMIN_EMAIL else 0

        db.execute(
            'INSERT INTO users (email, username, password_hash, salt, full_name, is_admin, email_verified) VALUES (?, ?, ?, ?, ?, ?, 1)',
            (google_email, username, password_hash, salt, google_name, is_admin)
        )
        db.commit()

        user = db.execute('SELECT * FROM users WHERE email = ?', (google_email,)).fetchone()

        # Save Google profile picture as avatar
        if google_picture:
            db.execute('UPDATE users SET avatar = ? WHERE id = ?', (google_picture, user['id']))
            db.commit()

        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session.pop('pending_verification_email', None)
        log_activity(user['id'], 'signup_google')

        return redirect(url_for('dashboard_page') + '?welcome=1')

# ============================================
# AI CHATBOT API
# ============================================
# DASHBOARD SEARCH — unified search across categories
# ============================================
@app.route('/api/dashboard-search')
def api_dashboard_search():
    q = request.args.get('q', '').strip().lower()
    cat = request.args.get('cat', 'scholarships').lower()
    page = int(request.args.get('page', 1))
    per_page = 10

    results = []

    if cat == 'scholarships':
        for s in get_scholarships():
            s_str = json.dumps(s).lower()
            if q and q not in s_str:
                continue
            results.append({
                'name': s.get('name', s.get('title', 'Scholarship')),
                'sub': ' · '.join(filter(None, [s.get('country', ''), s.get('funding', '')])),
                'meta': s.get('deadline', ''),
                'link': s.get('link', s.get('url', '')),
                'type': 'scholarship',
            })
    elif cat == 'universities':
        for u in get_universities():
            u_str = json.dumps(u).lower()
            if q and q not in u_str:
                continue
            results.append({
                'name': u.get('name', u.get('university', 'University')),
                'sub': ' · '.join(filter(None, [u.get('country', ''), f"Rank: {u.get('ranking', 'N/A')}"])),
                'meta': u.get('tuition', ''),
                'link': u.get('link', u.get('url', '')),
                'type': 'university',
            })
    elif cat == 'opportunities':
        for o in get_opportunities():
            o_str = json.dumps(o).lower()
            if q and q not in o_str:
                continue
            results.append({
                'name': o.get('name', o.get('title', 'Opportunity')),
                'sub': ' · '.join(filter(None, [o.get('type', ''), o.get('country', '')])),
                'meta': o.get('deadline', ''),
                'link': o.get('link', o.get('url', '')),
                'type': 'opportunity',
            })
    elif cat == 'internships':
        for o in get_opportunities():
            o_str = json.dumps(o).lower()
            o_type = (o.get('type', '') or '').lower()
            if 'intern' not in o_str and 'intern' not in o_type:
                continue
            if q and q not in o_str:
                continue
            results.append({
                'name': o.get('name', o.get('title', 'Internship')),
                'sub': ' · '.join(filter(None, [o.get('type', ''), o.get('country', '')])),
                'meta': o.get('deadline', ''),
                'link': o.get('link', o.get('url', '')),
                'type': 'internship',
            })

    total = len(results)
    start = (page - 1) * per_page
    return jsonify({
        'total': total,
        'page': page,
        'results': results[start:start + per_page],
    })


# AI-POWERED PERSONALIZED RECOMMENDATIONS
# ============================================
@app.route('/api/ai-recommendations')
@login_required
def api_ai_recommendations():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Login required'}), 401

    profile_name = (user['full_name'] or user['username'] or 'Student').split()[0]
    profile_country = user['country'] or ''
    profile_field = user['field_of_study'] or ''
    profile_level = user['education_level'] or ''
    profile_interests = user['interests'] or ''
    profile_gpa = user['gpa'] or ''

    if not profile_country and not profile_field:
        return jsonify({'error': 'incomplete_profile', 'message': 'Complete your profile first'})

    # Validate field of study
    field_warning = None
    field_valid = True
    if profile_field:
        is_valid, cleaned, note = validate_field_of_study(profile_field)
        if not is_valid:
            field_valid = False
            suggestion_text = f" Did you mean \"{note}\"?" if note else ""
            field_warning = f"We couldn't recognize \"{profile_field}\" as a field of study.{suggestion_text} Showing general recommendations for all fields. Update your profile with a recognized field (e.g., Computer Science, Medicine, Business, Engineering, Law, Nursing, Psychology, Journalism) for personalized matches."
            profile_field = ''  # Treat as empty so they get general recommendations

    # Gather top candidates from data
    scholarships = get_scholarships()[:200]
    universities = get_universities()[:100]

    schol_summaries = []
    for s in scholarships:
        schol_summaries.append(f"- {s.get('name','?')} | {s.get('country','')} | {s.get('level','')} | {s.get('field','')} | {s.get('funding','')}")

    uni_summaries = []
    for u in universities:
        uni_summaries.append(f"- {u.get('name', u.get('university','?'))} | {u.get('country','')} | Rank: {u.get('ranking','N/A')} | {u.get('tuition','')}")

    system_prompt = f"""You are ScholarFinder's AI matching engine. Given a student profile and available scholarships/universities, pick the BEST matches.

STUDENT PROFILE:
- Name: {profile_name}
- Country: {profile_country}
- Field: {profile_field}
- Level: {profile_level}
- GPA: {profile_gpa}
- Interests: {profile_interests}

AVAILABLE SCHOLARSHIPS:
{chr(10).join(schol_summaries[:80])}

AVAILABLE UNIVERSITIES:
{chr(10).join(uni_summaries[:50])}

Return ONLY valid JSON (no markdown, no code blocks):
{{
    "scholarships": [
        {{"name": "<exact scholarship name from list>", "reason": "<1 sentence why this matches>"}},
        ... (pick 5-8 best matches)
    ],
    "universities": [
        {{"name": "<exact university name from list>", "reason": "<1 sentence why this matches>"}},
        ... (pick 4-6 best matches)
    ],
    "summary": "<1 sentence speaking DIRECTLY to the student — use 'you/your' and their first name>"
}}

RULES:
- Only pick scholarships/universities from the lists above — use EXACT names
- Match based on country, field, education level, and interests
- Rank by relevance — best match first
- Be specific in reasons — reference actual profile details
- If field is broad like "any", prioritize country and level matches
- TONE: Write as if you're their personal advisor who knows them. Address them directly using "you/your" and their first name. Say "{profile_name}, you have..." NOT "{profile_name} has...". Say "this fits your interest in..." NOT "this fits the student's interest in...". Make it feel personal — like the platform was built just for them"""

    try:
        ai_payload = json.dumps({
            'model': GROQ_MODEL,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': 'Match me with the best scholarships and universities.'}
            ],
            'max_tokens': 2000,
            'temperature': 0.3
        }).encode('utf-8')

        result = call_groq(ai_payload)
        ai_text = result['choices'][0]['message']['content'].strip()

        if ai_text.startswith('```'):
            ai_text = ai_text.split('\n', 1)[1] if '\n' in ai_text else ai_text[3:]
        if ai_text.endswith('```'):
            ai_text = ai_text[:-3]
        ai_text = ai_text.strip()

        ai_data = json.loads(ai_text)

        # Enrich with links from actual data
        schol_map = {s.get('name','').lower(): s for s in scholarships}
        uni_map = {u.get('name', u.get('university','')).lower(): u for u in universities}

        for item in ai_data.get('scholarships', []):
            src = schol_map.get(item['name'].lower(), {})
            item['country'] = src.get('country', '')
            item['funding'] = src.get('funding', '')
            item['deadline'] = src.get('deadline', '')
            item['link'] = src.get('link', src.get('url', ''))
            item['level'] = src.get('level', '')

        for item in ai_data.get('universities', []):
            src = uni_map.get(item['name'].lower(), {})
            item['country'] = src.get('country', '')
            item['ranking'] = src.get('ranking', src.get('ranking_tier', ''))
            item['link'] = src.get('website', src.get('link', src.get('url', '')))

        ai_data['ai_powered'] = True
        if field_warning:
            ai_data['field_warning'] = field_warning
        return jsonify(ai_data)

    except Exception as e:
        print(f'AI Recommendations error: {e}')
        import traceback; traceback.print_exc()
        # Fallback to basic matching
        matched_s = match_scholarships(user)[:6]
        return jsonify({
            'scholarships': [{'name': s.get('name', ''), 'reason': 'Matched by profile', 'country': s.get('country',''), 'funding': s.get('funding',''), 'deadline': s.get('deadline',''), 'link': s.get('link', s.get('url','')), 'level': s.get('level','')} for s in matched_s],
            'universities': [],
            'summary': 'Showing basic matches. AI matching temporarily unavailable.',
            'ai_powered': False
        })

@app.route('/api/chat', methods=['POST'])
def api_chat():
    """Smart chatbot — searches all data to answer questions"""
    data = request.get_json()
    if not data or not data.get('message'):
        return jsonify({'error': 'No message'}), 400

    query = data['message'].strip().lower()
    user = get_current_user()

    # Log the question
    if user:
        try:
            db = get_db()
            db.execute(
                'INSERT INTO search_log (user_id, query, category) VALUES (?, ?, ?)',
                (session.get('user_id'), query, 'chat')
            )
            db.commit()
        except Exception:
            pass

    # 1. Check FAQ first
    faqs = get_faq()
    for faq in faqs:
        q_text = (faq.get('question', '') or '').lower()
        keywords = [w for w in query.split() if len(w) > 2]
        matches = sum(1 for k in keywords if k in q_text)
        if matches >= 2 or (len(keywords) == 1 and keywords[0] in q_text):
            return jsonify({
                'reply': faq.get('answer', 'I found a match but no answer is available.'),
                'source': 'FAQ',
                'related': []
            })

    # 2. Check for scholarship queries
    scholarship_keywords = ['scholarship', 'fund', 'grant', 'financial', 'tuition', 'aid', 'free', 'money', 'pay', 'afford']
    if any(k in query for k in scholarship_keywords):
        scholarships = get_scholarships()
        matches = []
        for s in scholarships:
            s_str = json.dumps(s).lower()
            score = sum(1 for w in query.split() if len(w) > 2 and w in s_str)
            if score > 0:
                matches.append((score, s))
        matches.sort(key=lambda x: x[0], reverse=True)
        top = [s for _, s in matches[:5]]

        if top:
            names = '\n'.join([f"• **{s.get('name', s.get('title', 'Unknown'))}** — {s.get('country', 'Various')} ({s.get('level', 'All levels')})" for s in top])
            reply = f"Here are some scholarships matching your question:\n\n{names}\n\nUse the Scholarships page to search and filter all {len(scholarships)} scholarships!"
        else:
            reply = f"I have {len(scholarships)} scholarships in the database. Try searching on the Scholarships page with specific keywords like a country or field of study."

        return jsonify({'reply': reply, 'source': 'Scholarships', 'related': [s.get('name', '') for s in top[:3]]})

    # 3. Check for university queries
    uni_keywords = ['university', 'universities', 'college', 'school', 'campus', 'ranking', 'admission']
    if any(k in query for k in uni_keywords):
        universities = get_universities()
        matches = []
        for u in universities:
            u_str = json.dumps(u).lower()
            score = sum(1 for w in query.split() if len(w) > 2 and w in u_str)
            if score > 0:
                matches.append((score, u))
        matches.sort(key=lambda x: x[0], reverse=True)
        top = [u for _, u in matches[:5]]

        if top:
            names = '\n'.join([f"• **{u.get('name', u.get('university', 'Unknown'))}** — {u.get('country', '')} (Rank: {u.get('ranking', 'N/A')})" for u in top])
            reply = f"Here are universities matching your query:\n\n{names}\n\nBrowse all {len(universities)} universities on the Universities page!"
        else:
            reply = f"I have {len(universities)} universities in the database. Try the Universities page to search by country or ranking."

        return jsonify({'reply': reply, 'source': 'Universities', 'related': [u.get('name', '') for u in top[:3]]})

    # 4. Check for opportunity queries
    opp_keywords = ['internship', 'research', 'competition', 'fellowship', 'exchange', 'summer', 'program', 'opportunity']
    if any(k in query for k in opp_keywords):
        opportunities = get_opportunities()
        matches = []
        for o in opportunities:
            o_str = json.dumps(o).lower()
            score = sum(1 for w in query.split() if len(w) > 2 and w in o_str)
            if score > 0:
                matches.append((score, o))
        matches.sort(key=lambda x: x[0], reverse=True)
        top = [o for _, o in matches[:5]]

        if top:
            names = '\n'.join([f"• **{o.get('name', o.get('title', 'Unknown'))}** — {o.get('type', 'Opportunity')}" for o in top])
            reply = f"Here are opportunities matching your query:\n\n{names}\n\nCheck the Opportunities page for all {len(opportunities)} listings!"
        else:
            reply = f"I have {len(opportunities)} opportunities including internships, research programs, competitions, and fellowships. Browse them on the Opportunities page."

        return jsonify({'reply': reply, 'source': 'Opportunities', 'related': [o.get('name', '') for o in top[:3]]})

    # 5. Check for visa queries
    visa_keywords = ['visa', 'passport', 'travel', 'immigration', 'permit']
    if any(k in query for k in visa_keywords):
        visas = get_visa_guides()
        matches = []
        for v in visas:
            v_str = json.dumps(v).lower()
            if any(w in v_str for w in query.split() if len(w) > 2):
                matches.append(v)
        if matches:
            countries = ', '.join([v.get('country', 'Unknown') for v in matches[:5]])
            reply = f"I have visa guides for: {countries}. Visit the Visa Guide section on the Telegram bot for detailed step-by-step info."
        else:
            reply = f"I have student visa guides for {len(visas)} countries. What country are you interested in?"
        return jsonify({'reply': reply, 'source': 'Visa Guides', 'related': []})

    # 6. Check for test prep queries
    test_keywords = ['ielts', 'toefl', 'sat', 'gre', 'gmat', 'duolingo', 'test', 'exam', 'english']
    if any(k in query for k in test_keywords):
        tests = get_test_prep()
        reply = "We have test prep guides for IELTS, TOEFL, SAT, GRE, and Duolingo English Test. Each includes format overview, tips, free resources, and score requirements. Check the Test Prep section for details!"
        return jsonify({'reply': reply, 'source': 'Test Prep', 'related': []})

    # 7. Check for cost/living queries
    cost_keywords = ['cost', 'living', 'expensive', 'cheap', 'rent', 'budget', 'afford', 'city', 'cities']
    if any(k in query for k in cost_keywords):
        costs = get_cost_of_living()
        matches = []
        for c in costs:
            c_str = json.dumps(c).lower()
            if any(w in c_str for w in query.split() if len(w) > 2):
                matches.append(c)
        if matches:
            cities = '\n'.join([f"• **{c.get('city', 'Unknown')}**, {c.get('country', '')} — ~${c.get('monthly_total', c.get('total', 'N/A'))}/month" for c in matches[:5]])
            reply = f"Here's what I found:\n\n{cities}\n\nCompare all {len(costs)} cities on our platform!"
        else:
            reply = f"I have cost of living data for {len(costs)} student cities worldwide. Which city or country are you interested in?"
        return jsonify({'reply': reply, 'source': 'Cost of Living', 'related': []})

    # 8. Greetings
    greetings = ['hi', 'hello', 'hey', 'sup', 'yo', 'good morning', 'good afternoon', 'good evening']
    if any(g in query for g in greetings):
        stats = {
            'scholarships': len(get_scholarships()),
            'universities': len(get_universities()),
            'opportunities': len(get_opportunities()),
        }
        reply = f"Hey there! 👋 Welcome to ScholarFinder!\n\nI can help you find:\n• 🎯 {stats['scholarships']} Scholarships\n• 🏫 {stats['universities']} Universities\n• 🚀 {stats['opportunities']} Opportunities\n• 💰 Cost of living comparisons\n• 🛂 Visa guides\n• 📝 Test prep tips\n\nJust ask me anything — like \"scholarships in Canada\" or \"engineering universities\"!"
        return jsonify({'reply': reply, 'source': 'Welcome', 'related': []})

    # 9. Help / what can you do
    help_keywords = ['help', 'what can', 'what do', 'how do', 'features', 'guide']
    if any(k in query for k in help_keywords):
        reply = "Here's what I can help with:\n\n• 🎯 **Scholarship search** — \"Find scholarships for engineering in Europe\"\n• 🏫 **University info** — \"Top universities in Canada\"\n• 🚀 **Opportunities** — \"Internships in tech\"\n• 💰 **Cost of living** — \"How much to live in London?\"\n• 🛂 **Visa info** — \"Student visa for USA\"\n• 📝 **Test prep** — \"IELTS tips\"\n\nTry asking a specific question!"
        return jsonify({'reply': reply, 'source': 'Help', 'related': []})

    # 10. Global search fallback — search everything
    all_data = []
    for s in get_scholarships():
        all_data.append(('scholarship', s.get('name', s.get('title', '')), json.dumps(s).lower()))
    for u in get_universities():
        all_data.append(('university', u.get('name', u.get('university', '')), json.dumps(u).lower()))
    for o in get_opportunities():
        all_data.append(('opportunity', o.get('name', o.get('title', '')), json.dumps(o).lower()))

    words = [w for w in query.split() if len(w) > 2]
    results = []
    for dtype, name, data_str in all_data:
        score = sum(1 for w in words if w in data_str)
        if score > 0:
            results.append((score, dtype, name))
    results.sort(key=lambda x: x[0], reverse=True)

    if results:
        top5 = results[:5]
        lines = [f"• {r[2]} ({r[1]})" for r in top5]
        reply = f"Here's what I found for \"{data['message']}\":\n\n" + '\n'.join(lines) + f"\n\n{len(results)} total results. Use the search pages for more!"
        return jsonify({'reply': reply, 'source': 'Search', 'related': []})

    # Nothing found
    reply = "I'm not sure about that one. Try asking about:\n• Scholarships (e.g., \"scholarships in Germany\")\n• Universities (e.g., \"top engineering schools\")\n• Opportunities, visa guides, test prep, or cost of living\n\nOr browse the pages above!"
    return jsonify({'reply': reply, 'source': 'Default', 'related': []})



# ============================================
# SCHOLARSHIP DATABASE MANAGEMENT
# ============================================
def init_scholarship_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS scholarship_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            scholarship_name TEXT NOT NULL,
            data TEXT DEFAULT '{}',
            source TEXT DEFAULT 'webhook',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS link_health (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scholarship_name TEXT NOT NULL,
            url TEXT NOT NULL,
            status TEXT DEFAULT 'unknown',
            last_checked DATETIME,
            fail_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(scholarship_name)
        );
    """)
    db.commit()
    db.close()

init_scholarship_db()

def save_scholarships(data):
    path = os.path.join(DATA_DIR, 'scholarships.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    clear_json_cache('scholarships.json')

def save_opportunities(data):
    path = os.path.join(DATA_DIR, 'opportunities.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    clear_json_cache('opportunities.json')


# ============================================
# WEBHOOK — Scholarship Management
# ============================================
def verify_webhook(req):
    token = req.headers.get('X-Webhook-Secret') or req.args.get('secret')
    return token == WEBHOOK_SECRET

@app.route('/webhook/scholarships', methods=['POST'])
def webhook_scholarships():
    if not verify_webhook(request):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON body'}), 400

    action = data.get('action', '')  # add, update, remove, check_links, bulk_add
    result = {'action': action}

    scholarships = get_scholarships()

    if action == 'add':
        # Add a new scholarship
        new_schol = data.get('scholarship', {})
        if not new_schol.get('name'):
            return jsonify({'error': 'Scholarship name required'}), 400

        # Check for duplicates
        existing = [s for s in scholarships if s.get('name', '').lower() == new_schol['name'].lower()]
        if existing:
            return jsonify({'error': 'Scholarship already exists', 'name': new_schol['name']}), 409

        scholarships.append(new_schol)
        save_scholarships(scholarships)

        # Log
        db = get_db()
        db.execute('INSERT INTO scholarship_updates (action, scholarship_name, data, source) VALUES (?, ?, ?, ?)',
                   ('add', new_schol['name'], json.dumps(new_schol), data.get('source', 'webhook')))
        db.commit()

        result['success'] = True
        result['total'] = len(scholarships)
        result['message'] = f"Added: {new_schol['name']}"

    elif action == 'bulk_add':
        # Add multiple scholarships
        new_schols = data.get('scholarships', [])
        if not new_schols:
            return jsonify({'error': 'No scholarships provided'}), 400

        added = 0
        skipped = 0
        existing_names = {s.get('name', '').lower() for s in scholarships}

        for s in new_schols:
            if not s.get('name'):
                skipped += 1
                continue
            if s['name'].lower() in existing_names:
                skipped += 1
                continue
            scholarships.append(s)
            existing_names.add(s['name'].lower())
            added += 1

        save_scholarships(scholarships)
        result['success'] = True
        result['added'] = added
        result['skipped'] = skipped
        result['total'] = len(scholarships)

    elif action == 'update':
        # Update an existing scholarship
        name = data.get('name', '')
        updates = data.get('updates', {})
        if not name:
            return jsonify({'error': 'Scholarship name required'}), 400

        found = False
        for i, s in enumerate(scholarships):
            if s.get('name', '').lower() == name.lower():
                scholarships[i].update(updates)
                found = True
                break

        if not found:
            return jsonify({'error': 'Scholarship not found', 'name': name}), 404

        save_scholarships(scholarships)

        db = get_db()
        db.execute('INSERT INTO scholarship_updates (action, scholarship_name, data, source) VALUES (?, ?, ?, ?)',
                   ('update', name, json.dumps(updates), data.get('source', 'webhook')))
        db.commit()

        result['success'] = True
        result['message'] = f"Updated: {name}"

    elif action == 'remove':
        # Remove a scholarship
        name = data.get('name', '')
        if not name:
            return jsonify({'error': 'Scholarship name required'}), 400

        original_len = len(scholarships)
        scholarships = [s for s in scholarships if s.get('name', '').lower() != name.lower()]

        if len(scholarships) == original_len:
            return jsonify({'error': 'Scholarship not found', 'name': name}), 404

        save_scholarships(scholarships)

        db = get_db()
        db.execute('INSERT INTO scholarship_updates (action, scholarship_name, source) VALUES (?, ?, ?)',
                   ('remove', name, data.get('source', 'webhook')))
        db.commit()

        result['success'] = True
        result['total'] = len(scholarships)
        result['message'] = f"Removed: {name}"

    elif action == 'check_links':
        # Check which scholarship links are broken
        broken = []
        checked = 0
        for s in scholarships:
            link = s.get('link', '')
            if not link or not link.startswith('http'):
                continue
            try:
                req = urllib.request.Request(link, method='HEAD')
                req.add_header('User-Agent', 'ScholarFinder-LinkChecker/1.0')
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status >= 400:
                        broken.append({'name': s.get('name', '?'), 'link': link, 'status': resp.status})
                checked += 1
            except Exception as e:
                broken.append({'name': s.get('name', '?'), 'link': link, 'error': str(e)})
                checked += 1
            if checked >= 20:  # Limit per request to avoid timeout
                break

        result['success'] = True
        result['checked'] = checked
        result['broken'] = broken
        result['broken_count'] = len(broken)

    elif action == 'stats':
        # Get scholarship stats
        countries = {}
        levels = {}
        for s in scholarships:
            c = s.get('country', 'Unknown')
            countries[c] = countries.get(c, 0) + 1
            for l in (s.get('level', []) if isinstance(s.get('level'), list) else [s.get('level', 'Unknown')]):
                levels[l] = levels.get(l, 0) + 1

        result['success'] = True
        result['total'] = len(scholarships)
        result['countries'] = dict(sorted(countries.items(), key=lambda x: x[1], reverse=True))
        result['levels'] = levels
        result['with_links'] = len([s for s in scholarships if s.get('link')])
        result['with_deadlines'] = len([s for s in scholarships if s.get('deadline')])

    elif action == 'list_expired':
        # List scholarships with passed deadlines
        now = datetime.now()
        expired = []
        for s in scholarships:
            dl = s.get('deadline', '')
            if not dl or dl.lower() in ('varies', 'rolling', 'varies by university', 'ongoing'):
                continue
            try:
                dl_date = datetime.strptime(dl, '%B %d, %Y')
                if dl_date < now:
                    expired.append({'name': s.get('name', '?'), 'deadline': dl, 'country': s.get('country', '?')})
            except:
                pass

        result['success'] = True
        result['expired'] = expired
        result['expired_count'] = len(expired)

    else:
        return jsonify({'error': f'Unknown action: {action}', 'valid_actions': ['add', 'bulk_add', 'update', 'remove', 'check_links', 'stats', 'list_expired']}), 400

    return jsonify(result)


@app.route('/webhook/scholarships/secret', methods=['GET'])
@admin_required
def get_webhook_secret():
    return jsonify({'webhook_secret': WEBHOOK_SECRET, 'endpoint': request.host_url.rstrip('/') + '/webhook/scholarships'})


# ============================================
# WEBHOOK — Opportunities Management
# ============================================
@app.route('/webhook/opportunities', methods=['POST'])
def webhook_opportunities():
    if not verify_webhook(request):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON body'}), 400

    action = data.get('action', '')
    opportunities = get_opportunities()

    if action == 'bulk_add':
        new_opps = data.get('opportunities', [])
        if not new_opps:
            return jsonify({'error': 'No opportunities provided'}), 400

        added = 0
        skipped = 0
        existing_names = {o.get('name', '').lower() for o in opportunities}

        for o in new_opps:
            if not o.get('name'):
                skipped += 1
                continue
            if o['name'].lower() in existing_names:
                skipped += 1
                continue
            opportunities.append(o)
            existing_names.add(o['name'].lower())
            added += 1

        if added:
            save_opportunities(opportunities)

        return jsonify({
            'action': 'bulk_add',
            'success': True,
            'added': added,
            'skipped': skipped,
            'total': len(opportunities)
        })

    return jsonify({'error': f'Unknown action: {action}'}), 400


# ============================================
# DAILY SCRAPER TRIGGER
# ============================================
@app.route('/webhook/scraper/run', methods=['POST'])
def webhook_scraper_run():
    if not verify_webhook(request):
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        import importlib, io, logging as _log
        import scholarship_scraper
        importlib.reload(scholarship_scraper)  # Always pick up latest code

        # Capture log output for debug
        debug = request.args.get('debug') == '1'
        log_capture = io.StringIO()
        if debug:
            handler = _log.StreamHandler(log_capture)
            handler.setLevel(_log.DEBUG)
            scholarship_scraper.log.addHandler(handler)

        result = scholarship_scraper.run()
        resp = {'success': True, 'result': result}

        if debug:
            scholarship_scraper.log.removeHandler(handler)
            resp['log'] = log_capture.getvalue()[-5000:]  # Last 5KB of logs

        return jsonify(resp)
    except Exception as e:
        import traceback
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500


# ============================================
# ERROR HANDLERS
# ============================================
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Server error'}), 500
    return render_template('500.html'), 500

# ============================================
# INIT & RUN
# ============================================
# SEO ROUTES
# ============================================
@app.route('/robots.txt')
def robots():
    return """User-agent: *
Allow: /
Sitemap: /sitemap.xml
""", 200, {'Content-Type': 'text/plain'}

@app.route('/sitemap.xml')
def sitemap():
    from flask import make_response
    base = request.host_url.rstrip('/')
    pages = ['/', '/scholarships', '/universities', '/opportunities', '/cost-of-living',
             '/visa-guide', '/test-prep', '/faq', '/tools/essay-rater', '/tools/resume-review', '/tools/school-matcher',
             '/agents/scout', '/agents/writer', '/agents/profiler', '/agents/tracker', '/agents/advisor', '/agents/prep']
    xml = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for p in pages:
        xml.append(f'<url><loc>{base}{p}</loc><changefreq>weekly</changefreq></url>')
    xml.append('</urlset>')
    resp = make_response('\n'.join(xml))
    resp.headers['Content-Type'] = 'application/xml'
    return resp

# ============================================
init_db()

init_db()
_init_rate_limit_table()


# ============================================
# AI AGENT PROXY — keeps API key server-side
# ============================================
# GROQ config moved to top

@app.route('/api/ai/chat', methods=['POST'])
def api_ai_chat():
    """Proxy AI requests through the server so API key stays hidden"""
    data = request.get_json()
    if not data or not data.get('messages'):
        return jsonify({'error': 'No messages provided'}), 400

    messages = data['messages']
    max_tokens = min(data.get('max_tokens', 1024), 2500)

    try:
        import urllib.request
        req_data = json.dumps({
            'model': GROQ_MODEL,
            'messages': messages,
            'max_tokens': max_tokens,
            'temperature': 0.7
        }).encode('utf-8')

        result = call_groq(req_data)
        content = result['choices'][0]['message']['content']
        return jsonify({'content': content})
    except urllib.error.HTTPError as he:
        error_body = ''
        try:
            error_body = he.read().decode('utf-8')
        except:
            pass
        print(f'Groq API error {he.code}: {error_body}')
        return jsonify({'error': f'AI service error ({he.code}). Please try again.', 'detail': error_body}), 500
    except Exception as e:
        print(f'AI chat error: {e}')
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)



