import os
import json
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, render_template_string, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

app = Flask(__name__)
APP_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = Path(os.environ.get('UPLOAD_PATH', str(APP_DIR / 'uploads')))
UPLOAD_FOLDER.mkdir(exist_ok=True)
PRIVATE_UPLOAD_FOLDER = Path(os.environ.get('PRIVATE_UPLOAD_PATH', str(APP_DIR / 'private_uploads')))
PRIVATE_UPLOAD_FOLDER.mkdir(exist_ok=True)

app.config['DATABASE'] = os.environ.get('DATABASE_PATH', str(APP_DIR / 'social_media.db'))
app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL', '').strip()
secret_key = os.environ.get('SECRET_KEY', '').strip()
production_mode = os.environ.get('APP_ENV', '').lower() == 'production' or os.environ.get('RENDER', '').lower() in {'1', 'true', 'yes'}
if production_mode and not secret_key:
    raise RuntimeError('SECRET_KEY must be configured in production.')
app.config['SECRET_KEY'] = secret_key or 'local-development-secret-key'
app.config['SESSION_COOKIE_SECURE'] = production_mode
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['CSRF_ENABLED'] = True
app.config['AUTH_RATE_LIMITS_ENABLED'] = True
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024
app.config['MAX_VIDEO_MINUTES'] = 10


def csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


def rate_limit_subject_hash(value):
    return hmac.new(
        app.config['SECRET_KEY'].encode('utf-8'),
        value.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()


def inspect_message_media(upload):
    filename = secure_filename(upload.filename or '')
    extension = Path(filename).suffix.lower()
    stream = upload.stream
    original_position = stream.tell()
    header = stream.read(32)
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(original_position)
    if size > 50 * 1024 * 1024:
        raise ValueError('Message attachments must be 50 MB or smaller.')

    signatures = {
        '.jpg': ('image', header.startswith(b'\xff\xd8\xff')),
        '.jpeg': ('image', header.startswith(b'\xff\xd8\xff')),
        '.png': ('image', header.startswith(b'\x89PNG\r\n\x1a\n')),
        '.gif': ('image', header.startswith((b'GIF87a', b'GIF89a'))),
        '.webp': ('image', header.startswith(b'RIFF') and header[8:12] == b'WEBP'),
        '.mp4': ('video', len(header) >= 12 and header[4:8] == b'ftyp'),
        '.m4v': ('video', len(header) >= 12 and header[4:8] == b'ftyp'),
        '.mov': ('video', len(header) >= 12 and header[4:8] == b'ftyp'),
        '.avi': ('video', header.startswith(b'RIFF') and header[8:12] == b'AVI '),
        '.webm': ('video', header.startswith(b'\x1aE\xdf\xa3')),
        '.mp3': ('audio', header.startswith(b'ID3') or (len(header) > 1 and header[0] == 0xff and header[1] & 0xe0 == 0xe0)),
        '.wav': ('audio', header.startswith(b'RIFF') and header[8:12] == b'WAVE'),
        '.ogg': ('audio', header.startswith(b'OggS')),
        '.m4a': ('audio', len(header) >= 12 and header[4:8] == b'ftyp'),
    }
    detected = signatures.get(extension)
    if not filename or detected is None or not detected[1]:
        raise ValueError('That file type is not supported or does not match its contents.')
    return detected[0], f'{secrets.token_hex(16)}{extension}'


def rate_limit_exceeded(scope, subjects, limit, window_seconds):
    db = get_db()
    now = datetime.utcnow()
    cutoff = (now - timedelta(seconds=window_seconds)).isoformat(timespec='seconds')
    retention_cutoff = (now - timedelta(days=1)).isoformat(timespec='seconds')
    db.execute('DELETE FROM auth_rate_events WHERE occurred_at < ?', (retention_cutoff,))
    for subject in set(subjects):
        subject_hash = rate_limit_subject_hash(subject)
        attempts = fetch_scalar(
            'SELECT COUNT(*) FROM auth_rate_events WHERE scope = ? AND subject_hash = ? AND occurred_at >= ?',
            (scope, subject_hash, cutoff),
        ) or 0
        if attempts >= limit:
            return True
    return False


def record_rate_limit_events(scope, subjects):
    now = datetime.utcnow().isoformat(timespec='seconds')
    get_db().executemany(
        'INSERT INTO auth_rate_events (scope, subject_hash, occurred_at) VALUES (?, ?, ?)',
        [(scope, rate_limit_subject_hash(subject), now) for subject in set(subjects)],
    )
    get_db().commit()


app.jinja_env.globals['csrf_token'] = csrf_token


@app.before_request
def protect_state_changing_requests():
    if app.testing or not app.config['CSRF_ENABLED'] or request.method in {'GET', 'HEAD', 'OPTIONS', 'TRACE'}:
        return None
    expected = session.get('_csrf_token', '')
    supplied = request.form.get('csrf_token') or request.headers.get('X-CSRFToken', '')
    if not expected or not supplied or not hmac.compare_digest(str(expected), str(supplied)):
        return 'CSRF validation failed.', 400
    return None


@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=()')
    if production_mode:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return response


class PostgresDatabase:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, parameters=()):
        return self.connection.execute(sql.replace('?', '%s'), parameters)

    def executemany(self, sql, parameters):
        return self.connection.executemany(sql.replace('?', '%s'), parameters)

    def commit(self):
        self.connection.commit()

    def close(self):
        self.connection.close()


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        if app.config['DATABASE_URL']:
            if psycopg is None:
                raise RuntimeError('psycopg is required when DATABASE_URL is configured')
            db = PostgresDatabase(psycopg.connect(app.config['DATABASE_URL'], row_factory=dict_row))
        else:
            db = sqlite3.connect(app.config['DATABASE'])
            db.row_factory = sqlite3.Row
        g._database = db
    return db


def fetch_scalar(query, params=()):
    row = get_db().execute(query, params).fetchone()
    if row is None:
        return None
    try:
        return row[0]
    except (KeyError, IndexError, TypeError):
        if hasattr(row, 'values'):
            return next(iter(row.values()))
        return next(iter(row))


@app.teardown_appcontext
def close_db(_exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def harden_legacy_admin(db):
    legacy_admin = db.execute(
        'SELECT id, password_hash FROM users WHERE username = ? AND email = ?',
        ('admin', 'admin@zrydy.com'),
    ).fetchone()
    if legacy_admin and check_password_hash(legacy_admin['password_hash'], 'admin123'):
        db.execute(
            'UPDATE users SET password_hash = ?, is_admin = 0 WHERE id = ?',
            (generate_password_hash(secrets.token_urlsafe(32)), legacy_admin['id']),
        )


def provision_configured_admin(db):
    username = os.environ.get('BOOTSTRAP_ADMIN_USERNAME', '').strip().lower()
    email = os.environ.get('BOOTSTRAP_ADMIN_EMAIL', '').strip().lower()
    password = os.environ.get('BOOTSTRAP_ADMIN_PASSWORD', '')
    if not username and not email and not password:
        return
    if not username or not email or len(password) < 24:
        raise RuntimeError('Configure BOOTSTRAP_ADMIN_USERNAME, BOOTSTRAP_ADMIN_EMAIL, and a 24-character BOOTSTRAP_ADMIN_PASSWORD together.')
    existing = db.execute(
        'SELECT id, username, email FROM users WHERE username = ? OR email = ?',
        (username, email),
    ).fetchone()
    if existing:
        if existing['username'] != username or existing['email'] != email:
            raise RuntimeError('Bootstrap admin username/email conflicts with an existing account.')
        db.execute(
            'UPDATE users SET password_hash = ?, is_admin = 1 WHERE id = ?',
            (generate_password_hash(password), existing['id']),
        )
        return
    db.execute(
        'INSERT INTO users (full_name, username, email, password_hash, bio, profile_picture, is_admin) VALUES (?, ?, ?, ?, ?, ?, 1)',
        ('Platform Administrator', username, email, generate_password_hash(password), 'Platform administration', ''),
    )


def init_postgres_db():
    db = get_db()
    statements = [
        '''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, full_name TEXT NOT NULL, username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, bio TEXT DEFAULT '',
            profile_picture TEXT DEFAULT '', phone TEXT DEFAULT '', is_admin INTEGER NOT NULL DEFAULT 0
        )''',
        '''CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), caption TEXT,
            media_path TEXT, media_type TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS likes (
            id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
            post_id INTEGER NOT NULL REFERENCES posts(id), UNIQUE(user_id, post_id)
        )''',
        '''CREATE TABLE IF NOT EXISTS post_reactions (
            user_id INTEGER NOT NULL REFERENCES users(id), post_id INTEGER NOT NULL REFERENCES posts(id),
            reaction TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(user_id, post_id)
        )''',
        '''CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY, post_id INTEGER NOT NULL REFERENCES posts(id),
            user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY, sender_id INTEGER NOT NULL REFERENCES users(id),
            recipient_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
            media_path TEXT DEFAULT '', media_type TEXT DEFAULT 'text', is_read INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS groups (
            id SERIAL PRIMARY KEY, name TEXT NOT NULL, owner_id INTEGER NOT NULL REFERENCES users(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER NOT NULL REFERENCES groups(id), user_id INTEGER NOT NULL REFERENCES users(id),
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(group_id, user_id)
        )''',
        '''CREATE TABLE IF NOT EXISTS group_messages (
            id SERIAL PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES groups(id),
            sender_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS follows (
            follower_id INTEGER NOT NULL REFERENCES users(id), followed_id INTEGER NOT NULL REFERENCES users(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(follower_id, followed_id)
        )''',
        '''CREATE TABLE IF NOT EXISTS blocks (
            blocker_id INTEGER NOT NULL REFERENCES users(id), blocked_id INTEGER NOT NULL REFERENCES users(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(blocker_id, blocked_id)
        )''',
        '''CREATE TABLE IF NOT EXISTS saved_posts (
            user_id INTEGER NOT NULL REFERENCES users(id), post_id INTEGER NOT NULL REFERENCES posts(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id, post_id)
        )''',
        '''CREATE TABLE IF NOT EXISTS reposts (
            user_id INTEGER NOT NULL REFERENCES users(id), post_id INTEGER NOT NULL REFERENCES posts(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id, post_id)
        )''',
        '''CREATE TABLE IF NOT EXISTS stories (
            id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), caption TEXT DEFAULT '',
            media_path TEXT DEFAULT '', media_type TEXT DEFAULT 'text',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, expires_at TEXT NOT NULL
        )''',
        '''CREATE TABLE IF NOT EXISTS story_views (
            story_id INTEGER NOT NULL REFERENCES stories(id), user_id INTEGER NOT NULL REFERENCES users(id),
            viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(story_id, user_id)
        )''',
        '''CREATE TABLE IF NOT EXISTS polls (
            id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), question TEXT NOT NULL,
            options TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS poll_votes (
            poll_id INTEGER NOT NULL REFERENCES polls(id), user_id INTEGER NOT NULL REFERENCES users(id),
            option_index INTEGER NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(poll_id, user_id)
        )''',
        '''CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), actor_id INTEGER REFERENCES users(id),
            kind TEXT NOT NULL, body TEXT NOT NULL, target_url TEXT DEFAULT '', is_read INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS auth_rate_events (
            id SERIAL PRIMARY KEY, scope TEXT NOT NULL, subject_hash TEXT NOT NULL,
            occurred_at TEXT NOT NULL
        )''',
    ]
    for statement in statements:
        db.execute(statement)
    db.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS media_path TEXT DEFAULT ''")
    db.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS media_type TEXT DEFAULT 'text'")
    db.execute('ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_read INTEGER NOT NULL DEFAULT 0')
    harden_legacy_admin(db)
    provision_configured_admin(db)
    db.commit()


def init_db():
    with app.app_context():
        if app.config['DATABASE_URL']:
            init_postgres_db()
            return
        db = get_db()
        db.execute(
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                bio TEXT DEFAULT '',
                profile_picture TEXT DEFAULT '',
                phone TEXT DEFAULT '',
                is_admin INTEGER NOT NULL DEFAULT 0
            )
            '''
        )
        user_columns = {row['name'] for row in db.execute('PRAGMA table_info(users)').fetchall()}
        if 'phone' not in user_columns:
            db.execute('ALTER TABLE users ADD COLUMN phone TEXT DEFAULT ""')
        db.execute(
            '''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                caption TEXT,
                media_path TEXT,
                media_type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            '''
        )
        db.execute(
            '''
            CREATE TABLE IF NOT EXISTS likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                UNIQUE(user_id, post_id)
            )
            '''
        )
        db.execute('''CREATE TABLE IF NOT EXISTS post_reactions (
            user_id INTEGER NOT NULL, post_id INTEGER NOT NULL, reaction TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id, post_id),
            FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(post_id) REFERENCES posts(id)
        )''')
        db.execute(
            '''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(post_id) REFERENCES posts(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            '''
        )
        db.execute(
            '''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(recipient_id) REFERENCES users(id)
            )
            '''
        )
        message_columns = {row['name'] for row in db.execute('PRAGMA table_info(messages)').fetchall()}
        if 'media_path' not in message_columns:
            db.execute('ALTER TABLE messages ADD COLUMN media_path TEXT DEFAULT ""')
        if 'media_type' not in message_columns:
            db.execute('ALTER TABLE messages ADD COLUMN media_type TEXT DEFAULT "text"')
        if 'is_read' not in message_columns:
            db.execute('ALTER TABLE messages ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0')
        db.execute(
            '''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            )
            '''
        )
        db.execute(
            '''
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(group_id, user_id),
                FOREIGN KEY(group_id) REFERENCES groups(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            '''
        )
        db.execute(
            '''
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(group_id) REFERENCES groups(id),
                FOREIGN KEY(sender_id) REFERENCES users(id)
            )
            '''
        )
        db.execute('''CREATE TABLE IF NOT EXISTS follows (
            follower_id INTEGER NOT NULL, followed_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(follower_id, followed_id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS blocks (
            blocker_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(blocker_id, blocked_id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS saved_posts (
            user_id INTEGER NOT NULL, post_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(user_id, post_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(post_id) REFERENCES posts(id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS reposts (
            user_id INTEGER NOT NULL, post_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(user_id, post_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(post_id) REFERENCES posts(id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, caption TEXT DEFAULT '',
            media_path TEXT DEFAULT '', media_type TEXT DEFAULT 'text',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS story_views (
            story_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(story_id, user_id),
            FOREIGN KEY(story_id) REFERENCES stories(id), FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS polls (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, question TEXT NOT NULL,
            options TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS poll_votes (
            poll_id INTEGER NOT NULL, user_id INTEGER NOT NULL, option_index INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(poll_id, user_id),
            FOREIGN KEY(poll_id) REFERENCES polls(id), FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, actor_id INTEGER,
            kind TEXT NOT NULL, body TEXT NOT NULL, target_url TEXT DEFAULT '',
            is_read INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS auth_rate_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL,
            subject_hash TEXT NOT NULL, occurred_at TEXT NOT NULL
        )''')

        harden_legacy_admin(db)
        provision_configured_admin(db)
        db.commit()


def get_user_by_username(username):
    db = get_db()
    return db.execute(
        'SELECT * FROM users WHERE LOWER(username) = LOWER(?)',
        (username.strip(),),
    ).fetchone()


def get_user_by_id(user_id):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()


def get_all_users():
    db = get_db()
    return db.execute(
        'SELECT id, full_name, username, profile_picture FROM users WHERE id != ? ORDER BY username',
        (session['user_id'],),
    ).fetchall()


def get_unread_message_count():
    if 'user_id' not in session:
        return 0
    return fetch_scalar(
        'SELECT COUNT(*) AS total FROM messages WHERE recipient_id = ? AND is_read = 0',
        (session['user_id'],),
    ) or 0


def get_unread_notification_count():
    if 'user_id' not in session:
        return 0
    return fetch_scalar(
        'SELECT COUNT(*) AS total FROM notifications WHERE user_id = ? AND is_read = 0',
        (session['user_id'],),
    ) or 0


def notify(user_id, actor_id, kind, body, target_url=''):
    if user_id == actor_id:
        return
    get_db().execute(
        'INSERT INTO notifications (user_id, actor_id, kind, body, target_url) VALUES (?, ?, ?, ?, ?)',
        (user_id, actor_id, kind, body, target_url),
    )


@app.context_processor
def inject_message_notifications():
    return {
        'unread_message_count': get_unread_message_count(),
        'unread_notification_count': get_unread_notification_count(),
    }


def get_feed_posts(query='', feed_mode='for_you'):
    db = get_db()
    search = f'%{query.strip()}%'
    user_id = session.get('user_id', 0)
    following_clause = "" if feed_mode != 'following' else 'AND (p.user_id = ? OR EXISTS (SELECT 1 FROM follows f WHERE f.follower_id = ? AND f.followed_id = p.user_id))'
    saved_clause = 'AND EXISTS (SELECT 1 FROM saved_posts s WHERE s.user_id = ? AND s.post_id = p.id)' if feed_mode == 'saved' else ''
    blocked_clause = 'AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.blocker_id = ? AND b.blocked_id = p.user_id)'
    parameters = [query.strip(), search, search, search]
    if feed_mode == 'following':
        parameters.extend([user_id, user_id])
    if feed_mode == 'saved':
        parameters.append(user_id)
    parameters.append(user_id)
    rows = db.execute(
        '''
        SELECT p.*,
               u.username,
               u.full_name,
               u.profile_picture,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
               (SELECT COUNT(*) FROM reposts r WHERE r.post_id = p.id) AS repost_count
        FROM posts p
        JOIN users u ON u.id = p.user_id
        WHERE (? = '' OR p.caption LIKE ? OR u.username LIKE ? OR u.full_name LIKE ?)
        {following_clause}
        {saved_clause}
        {blocked_clause}
        ORDER BY p.created_at DESC
        '''.format(following_clause=following_clause, saved_clause=saved_clause, blocked_clause=blocked_clause),
        parameters,
    ).fetchall()
    return [dict(row) for row in rows]


def get_active_stories():
        db = get_db()
        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        viewer_id = session.get('user_id', 0)
        rows = db.execute(
                '''SELECT s.*, u.username, u.full_name, u.profile_picture,
                                    (SELECT COUNT(*) FROM story_views sv WHERE sv.story_id = s.id) AS view_count,
                                    EXISTS(SELECT 1 FROM story_views sv WHERE sv.story_id = s.id AND sv.user_id = ?) AS viewed
                     FROM stories s JOIN users u ON u.id = s.user_id
                     WHERE s.expires_at > ?
                         AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.blocker_id = ? AND b.blocked_id = s.user_id)
                     ORDER BY s.created_at DESC LIMIT 40''',
                (viewer_id, current_time, viewer_id),
        ).fetchall()
        return [dict(row) for row in rows]


def search_users(query):
    search = f'%{query.strip()}%'
    return get_db().execute(
        '''
         SELECT id, full_name, username, bio, profile_picture,
             (SELECT COUNT(*) FROM follows f WHERE f.followed_id = users.id) AS follower_count
        FROM users
                WHERE id != ?
                    AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.blocker_id = ? AND b.blocked_id = users.id)
                    AND (? = '' OR full_name LIKE ? OR username LIKE ?)
        ORDER BY username
        LIMIT 25
        ''',
                (session['user_id'], session['user_id'], query.strip(), search, search),
    ).fetchall()


def get_comments_for_post(post_id):
    db = get_db()
    rows = db.execute(
        '''
        SELECT c.*, u.username, u.full_name
        FROM comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.post_id = ?
        ORDER BY c.created_at ASC
        ''',
        (post_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session or get_user_by_id(session['user_id']) is None:
            session.clear()
            flash('Your session expired. Please log in again.', 'error')
            return redirect(url_for('login'))
        return view(*args, **kwargs)

    return wrapped_view


@app.route('/notifications')
@login_required
def notifications():
    db = get_db()
    rows = db.execute(
        '''
        SELECT m.id, m.body, m.created_at, u.full_name, u.username
        FROM messages m JOIN users u ON u.id = m.sender_id
        WHERE m.recipient_id = ? AND m.is_read = 0
        ORDER BY m.created_at DESC LIMIT 10
        ''',
        (session['user_id'],),
    ).fetchall()
    alerts = db.execute(
        '''SELECT n.*, u.username AS actor_username, u.full_name AS actor_name
           FROM notifications n LEFT JOIN users u ON u.id = n.actor_id
           WHERE n.user_id = ? AND n.is_read = 0
           ORDER BY n.created_at DESC LIMIT 20''',
        (session['user_id'],),
    ).fetchall()
    return jsonify({
        'count': len(rows) + len(alerts),
        'messages': [dict(row) for row in rows],
        'notifications': [dict(row) for row in alerts],
    })


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    if get_db().execute('SELECT 1 FROM messages WHERE media_path = ? LIMIT 1', (filename,)).fetchone():
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/message-uploads/<path:filename>')
@login_required
def uploaded_message_file(filename):
    safe_filename = secure_filename(filename)
    if not safe_filename or safe_filename != filename:
        abort(404)
    db = get_db()
    message = db.execute(
        '''SELECT media_type FROM messages
           WHERE media_path = ? AND (sender_id = ? OR recipient_id = ?)
           LIMIT 1''',
        (filename, session['user_id'], session['user_id']),
    ).fetchone()
    if message is None:
        abort(404)
    directory = PRIVATE_UPLOAD_FOLDER if (PRIVATE_UPLOAD_FOLDER / filename).is_file() else Path(app.config['UPLOAD_FOLDER'])
    response = send_from_directory(
        directory,
        filename,
        as_attachment=message['media_type'] == 'file',
        max_age=0,
    )
    response.headers['Cache-Control'] = 'private, no-store'
    response.headers['Content-Security-Policy'] = "default-src 'none'; img-src 'self'; media-src 'self'; sandbox"
    return response


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/health')
def health():
    try:
        fetch_scalar('SELECT 1')
    except Exception:
        return jsonify({'status': 'unhealthy'}), 503
    return jsonify({'status': 'ok'}), 200


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        signup_ip = f"ip:{request.remote_addr or 'unknown'}"
        if app.config['AUTH_RATE_LIMITS_ENABLED']:
            if rate_limit_exceeded('signup-ip', [signup_ip], 20, 3600):
                flash('Too many signup attempts. Please try again later.', 'error')
                return render_template('index.html'), 429
            record_rate_limit_events('signup-ip', [signup_ip])
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip().lower()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not full_name or not username or not email or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('index.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('index.html')

        existing = get_db().execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (username, email),
        ).fetchone()

        if existing:
            flash('That username or email already exists.', 'error')
            return render_template('index.html')

        db = get_db()
        db.execute(
            'INSERT INTO users (full_name, username, email, password_hash, bio, profile_picture, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (full_name, username, email, generate_password_hash(password), 'New to Zrydy', '', 0),
        )
        db.commit()

        user = get_user_by_username(username)
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = bool(user['is_admin'])
        session.permanent = True
        flash('Registration successful!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        account_subject = f"account:{username.casefold()}"
        ip_subject = f"ip:{request.remote_addr or 'unknown'}"
        if app.config['AUTH_RATE_LIMITS_ENABLED'] and (
            rate_limit_exceeded('login-account', [account_subject], 10, 900)
            or rate_limit_exceeded('login-ip', [ip_subject], 30, 900)
        ):
            flash('Invalid username or password. Please try again later.', 'error')
            return render_template('login.html'), 429

        user = get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            db = get_db()
            db.execute(
                'DELETE FROM auth_rate_events WHERE scope = ? AND subject_hash = ?',
                ('login-account', rate_limit_subject_hash(account_subject)),
            )
            db.commit()
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            session.permanent = True
            flash('Login successful!', 'success')
            next_url = request.args.get('next', '')
            parsed_next = urlsplit(next_url)
            if parsed_next.path.startswith('/') and not parsed_next.path.startswith('//') and not parsed_next.netloc and not parsed_next.scheme:
                return redirect(next_url)
            return redirect(url_for('dashboard'))

        if app.config['AUTH_RATE_LIMITS_ENABLED']:
            record_rate_limit_events('login-account', [account_subject])
            record_rate_limit_events('login-ip', [ip_subject])
        flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        flash('Self-service recovery is unavailable until verified email recovery is configured. Sign in to change your password or contact support.', 'error')
    return render_template('forgot_password.html')


@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    user = get_user_by_id(session['user_id'])
    if not check_password_hash(user['password_hash'], current_password):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('profile'))
    if len(new_password) < 12:
        flash('Choose a new password with at least 12 characters.', 'error')
        return redirect(url_for('profile'))
    if new_password != confirm_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('profile'))
    if check_password_hash(user['password_hash'], new_password):
        flash('Choose a password you have not used for this account.', 'error')
        return redirect(url_for('profile'))
    db = get_db()
    db.execute(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        (generate_password_hash(new_password), session['user_id']),
    )
    db.commit()
    flash('Password changed successfully.', 'success')
    return redirect(url_for('profile'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        if user is None:
            session.clear()
            flash('Your session expired. Please log in again.', 'error')
            return redirect(url_for('login'))
    else:
        user = {
            'full_name': 'Guest User',
            'username': 'guest',
            'bio': 'Welcome to Zrydy.',
            'profile_picture': '',
        }
    query = request.args.get('q', '').strip()
    feed_mode = request.args.get('feed', 'for_you')
    if feed_mode not in {'for_you', 'following', 'saved'}:
        feed_mode = 'for_you'
    posts = get_feed_posts(query, feed_mode)
    for post in posts:
        post['comments'] = get_comments_for_post(post['id'])
        reaction_rows = get_db().execute(
            'SELECT reaction, COUNT(*) AS total FROM post_reactions WHERE post_id = ? GROUP BY reaction',
            (post['id'],),
        ).fetchall()
        post['reaction_counts'] = {row['reaction']: row['total'] for row in reaction_rows}
        post['reaction_total'] = sum(post['reaction_counts'].values())
        my_reaction = get_db().execute(
            'SELECT reaction FROM post_reactions WHERE user_id = ? AND post_id = ?',
            (session.get('user_id', 0), post['id']),
        ).fetchone() if 'user_id' in session else None
        post['my_reaction'] = my_reaction['reaction'] if my_reaction else ''
        post['following_author'] = bool('user_id' in session and get_db().execute(
            'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
            (session['user_id'], post['user_id']),
        ).fetchone())
        post['reposted_by_me'] = bool(get_db().execute(
            'SELECT 1 FROM reposts WHERE user_id = ? AND post_id = ?',
            (session.get('user_id', 0), post['id']),
        ).fetchone()) if 'user_id' in session else False
    people = search_users(query) if 'user_id' in session else []
    if 'user_id' in session:
        db = get_db()
        people = [dict(person) for person in people]
        for person in people:
            person['following'] = bool(db.execute('SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?', (session['user_id'], person['id'])).fetchone())
            person['blocked'] = bool(db.execute('SELECT 1 FROM blocks WHERE blocker_id = ? AND blocked_id = ?', (session['user_id'], person['id'])).fetchone())
    return render_template(
        'dashboard.html', user=user, posts=posts, people=people, query=query,
        feed_mode=feed_mode, stories=get_active_stories(),
    )


@app.route('/stories/create', methods=['POST'])
@login_required
def create_story():
    caption = request.form.get('caption', '').strip()[:500]
    media = request.files.get('media')
    media_path = ''
    media_type = 'text'
    if media and media.filename:
        safe_name = secure_filename(media.filename)
        suffix = Path(safe_name).suffix.lower()
        media_type = 'image' if suffix in {'.png', '.jpg', '.jpeg', '.gif', '.webp'} else 'video' if suffix in {'.mp4', '.mov', '.webm'} else ''
        if not media_type:
            flash('Stories support images and videos only.', 'error')
            return redirect(url_for('dashboard'))
        media_path = f"{secrets.token_hex(8)}_{safe_name}"
        media.save(UPLOAD_FOLDER / media_path)
    if not caption and not media_path:
        flash('Add a photo, video, or short note to your story.', 'error')
        return redirect(url_for('dashboard'))
    expires_at = (datetime.utcnow() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    db = get_db()
    db.execute(
        'INSERT INTO stories (user_id, caption, media_path, media_type, expires_at) VALUES (?, ?, ?, ?, ?)',
        (session['user_id'], caption, media_path, media_type, expires_at),
    )
    db.commit()
    flash('Your story is live for 24 hours.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/stories/<int:story_id>/view', methods=['POST'])
@login_required
def view_story(story_id):
    db = get_db()
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    story = db.execute(
        'SELECT id, user_id FROM stories WHERE id = ? AND expires_at > ?',
        (story_id, now),
    ).fetchone()
    if story is None:
        return jsonify({'error': 'Story is no longer available.'}), 404
    existing = db.execute(
        'SELECT 1 FROM story_views WHERE story_id = ? AND user_id = ?',
        (story_id, session['user_id']),
    ).fetchone()
    if not existing:
        db.execute('INSERT INTO story_views (story_id, user_id) VALUES (?, ?)', (story_id, session['user_id']))
        db.commit()
    count = fetch_scalar('SELECT COUNT(*) FROM story_views WHERE story_id = ?', (story_id,)) or 0
    return jsonify({'viewed': True, 'viewCount': count})


@app.route('/live')
@login_required
def live():
    return render_template('live.html')


@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    db = get_db()
    user = get_user_by_id(user_id)
    if user is None:
        return 'Profile not found.', 404
    if 'user_id' in session and db.execute(
        'SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)',
        (session['user_id'], user_id, user_id, session['user_id']),
    ).fetchone():
        return 'Profile not found.', 404
    user = dict(user)
    user['follower_count'] = fetch_scalar('SELECT COUNT(*) FROM follows WHERE followed_id = ?', (user_id,)) or 0
    user['following_count'] = fetch_scalar('SELECT COUNT(*) FROM follows WHERE follower_id = ?', (user_id,)) or 0
    user['post_count'] = fetch_scalar('SELECT COUNT(*) FROM posts WHERE user_id = ?', (user_id,)) or 0
    user['like_count'] = fetch_scalar(
        'SELECT COUNT(*) FROM likes WHERE post_id IN (SELECT id FROM posts WHERE user_id = ?)',
        (user_id,),
    ) or 0
    user['following'] = bool('user_id' in session and db.execute(
        'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?', (session['user_id'], user_id),
    ).fetchone())
    posts = db.execute(
        '''SELECT p.*, (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count,
                  (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
                  (SELECT COUNT(*) FROM reposts r WHERE r.post_id = p.id) AS repost_count
           FROM posts p WHERE p.user_id = ? ORDER BY p.created_at DESC''',
        (user_id,),
    ).fetchall()
    reposts = db.execute(
        '''SELECT p.*, u.username, u.full_name, u.profile_picture,
                  (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count,
                  (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
                  (SELECT COUNT(*) FROM reposts r2 WHERE r2.post_id = p.id) AS repost_count
           FROM reposts r JOIN posts p ON p.id = r.post_id JOIN users u ON u.id = p.user_id
           WHERE r.user_id = ? ORDER BY r.created_at DESC''',
        (user_id,),
    ).fetchall()
    is_self = 'user_id' in session and session['user_id'] == user_id
    return render_template('public_profile.html', user=user, posts=posts, reposts=reposts, is_self=is_self)


@app.route('/user/<int:user_id>/follow', methods=['POST'])
@login_required
def toggle_follow(user_id):
    if user_id == session['user_id'] or get_user_by_id(user_id) is None:
        return redirect(request.referrer or url_for('dashboard'))
    db = get_db()
    existing = db.execute('SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?', (session['user_id'], user_id)).fetchone()
    if existing:
        db.execute('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?', (session['user_id'], user_id))
    else:
        db.execute('INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)', (session['user_id'], user_id))
        notify(user_id, session['user_id'], 'follow', f"{session.get('username', 'Someone')} started following you.", url_for('dashboard', q=session.get('username', '')))
    db.commit()
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/user/<int:user_id>/block', methods=['POST'])
@login_required
def toggle_block(user_id):
    if user_id == session['user_id']:
        return redirect(request.referrer or url_for('dashboard'))
    db = get_db()
    existing = db.execute('SELECT 1 FROM blocks WHERE blocker_id = ? AND blocked_id = ?', (session['user_id'], user_id)).fetchone()
    if existing:
        db.execute('DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?', (session['user_id'], user_id))
        flash('User unblocked.', 'success')
    else:
        db.execute('INSERT INTO blocks (blocker_id, blocked_id) VALUES (?, ?)', (session['user_id'], user_id))
        db.execute('DELETE FROM follows WHERE (follower_id = ? AND followed_id = ?) OR (follower_id = ? AND followed_id = ?)', (session['user_id'], user_id, user_id, session['user_id']))
        flash('User blocked.', 'success')
    db.commit()
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/notifications/read', methods=['POST'])
@login_required
def mark_notifications_read():
    db = get_db()
    db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (session['user_id'],))
    db.commit()
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/messages/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_conversation(user_id):
    db = get_db()
    db.execute(
        '''DELETE FROM messages WHERE (sender_id = ? AND recipient_id = ?)
           OR (sender_id = ? AND recipient_id = ?)''',
        (session['user_id'], user_id, user_id, session['user_id']),
    )
    db.commit()
    flash('Conversation deleted from your inbox.', 'success')
    return redirect(url_for('messages'))


@app.route('/messages')
@login_required
def messages():
    db = get_db()
    conversations = db.execute(
        '''
        SELECT u.id, u.full_name, u.username, u.profile_picture,
               m.body, m.created_at
        FROM users u
        JOIN messages m ON m.id = (
            SELECT m2.id FROM messages m2
            WHERE (m2.sender_id = ? AND m2.recipient_id = u.id)
               OR (m2.sender_id = u.id AND m2.recipient_id = ?)
            ORDER BY m2.created_at DESC, m2.id DESC LIMIT 1
        )
        WHERE u.id != ?
        ORDER BY m.created_at DESC
        ''',
        (session['user_id'], session['user_id'], session['user_id']),
    ).fetchall()
    groups = db.execute(
        '''
        SELECT g.id, g.name, COUNT(gm2.user_id) AS member_count
        FROM groups g
        JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = ?
        LEFT JOIN group_members gm2 ON gm2.group_id = g.id
        GROUP BY g.id
        ORDER BY g.created_at DESC
        ''',
        (session['user_id'],),
    ).fetchall()
    return render_template('messages.html', conversations=conversations, users=get_all_users(), groups=groups)


@app.route('/groups/create', methods=['POST'])
@login_required
def create_group():
    name = request.form.get('name', '').strip()
    member_ids = {session['user_id']}
    for value in request.form.getlist('member_ids'):
        if value.isdigit():
            member_ids.add(int(value))
    if not name:
        flash('Enter a group name.', 'error')
        return redirect(url_for('messages'))
    db = get_db()
    group = db.execute(
        'INSERT INTO groups (name, owner_id) VALUES (?, ?) RETURNING id',
        (name, session['user_id']),
    ).fetchone()
    db.executemany(
        'INSERT INTO group_members (group_id, user_id) VALUES (?, ?) ON CONFLICT DO NOTHING',
        [(group['id'], user_id) for user_id in member_ids],
    )
    db.commit()
    flash('Group created.', 'success')
    return redirect(url_for('group_conversation', group_id=group['id']))


@app.route('/groups/<int:group_id>', methods=['GET', 'POST'])
@login_required
def group_conversation(group_id):
    db = get_db()
    group = db.execute(
        '''
        SELECT g.* FROM groups g
        JOIN group_members gm ON gm.group_id = g.id
        WHERE g.id = ? AND gm.user_id = ?
        ''',
        (group_id, session['user_id']),
    ).fetchone()
    if group is None:
        flash('That group could not be found.', 'error')
        return redirect(url_for('messages'))
    if request.method == 'POST':
        body = request.form.get('body', '').strip()
        if body:
            db.execute(
                'INSERT INTO group_messages (group_id, sender_id, body) VALUES (?, ?, ?)',
                (group_id, session['user_id'], body),
            )
            db.commit()
        return redirect(url_for('group_conversation', group_id=group_id))
    group_messages = db.execute(
        '''
        SELECT gm.*, u.username, u.full_name
        FROM group_messages gm JOIN users u ON u.id = gm.sender_id
        WHERE gm.group_id = ? ORDER BY gm.created_at ASC, gm.id ASC
        ''',
        (group_id,),
    ).fetchall()
    members = db.execute(
        '''
        SELECT u.id, u.full_name, u.username
        FROM users u JOIN group_members gm ON gm.user_id = u.id
        WHERE gm.group_id = ? ORDER BY u.username
        ''',
        (group_id,),
    ).fetchall()
    return render_template('group_conversation.html', group=group, messages=group_messages, members=members)


@app.route('/messages/<int:user_id>', methods=['GET', 'POST'])
@login_required
def conversation(user_id):
    other_user = get_user_by_id(user_id)
    if other_user is None or other_user['id'] == session['user_id']:
        flash('That user could not be found.', 'error')
        return redirect(url_for('messages'))

    db = get_db()
    if request.method == 'POST':
        message_subject = f"user:{session['user_id']}"
        if app.config['AUTH_RATE_LIMITS_ENABLED'] and rate_limit_exceeded(
            'message-send', [message_subject], 120, 3600,
        ):
            return 'Message limit reached. Please try again later.', 429
        body = request.form.get('body', '').strip()
        media = request.files.get('media')
        media_path = ''
        media_type = 'text'
        if media and media.filename:
            try:
                media_type, media_path = inspect_message_media(media)
            except ValueError as error:
                flash(str(error), 'error')
                return redirect(url_for('conversation', user_id=user_id))
            media.save(PRIVATE_UPLOAD_FOLDER / media_path)
        if body or media_path:
            if app.config['AUTH_RATE_LIMITS_ENABLED']:
                record_rate_limit_events('message-send', [message_subject])
            db.execute(
                'INSERT INTO messages (sender_id, recipient_id, body, media_path, media_type, is_read) VALUES (?, ?, ?, ?, ?, 0)',
                (session['user_id'], user_id, body, media_path, media_type),
            )
            db.commit()
        return redirect(url_for('conversation', user_id=user_id))

    db.execute(
        'UPDATE messages SET is_read = 1 WHERE sender_id = ? AND recipient_id = ?',
        (user_id, session['user_id']),
    )
    db.commit()

    messages_between_users = db.execute(
        '''
        SELECT m.*, u.username AS sender_username
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE (m.sender_id = ? AND m.recipient_id = ?)
           OR (m.sender_id = ? AND m.recipient_id = ?)
        ORDER BY m.created_at ASC, m.id ASC
        ''',
        (session['user_id'], user_id, user_id, session['user_id']),
    ).fetchall()
    return render_template('conversation.html', other_user=other_user, messages=messages_between_users)


@app.route('/post/<int:post_id>/like', methods=['POST'])
@login_required
def toggle_like(post_id):
    db = get_db()
    existing = db.execute(
        'SELECT id FROM likes WHERE user_id = ? AND post_id = ?',
        (session['user_id'], post_id),
    ).fetchone()

    if existing:
        db.execute('DELETE FROM likes WHERE id = ?', (existing['id'],))
        flash('Like removed.', 'success')
    else:
        db.execute(
            'INSERT INTO likes (user_id, post_id) VALUES (?, ?)',
            (session['user_id'], post_id),
        )
        flash('Post liked.', 'success')

    db.commit()
    return redirect(url_for('dashboard'))


@app.route('/post/<int:post_id>/react', methods=['POST'])
@login_required
def react_to_post(post_id):
    allowed_reactions = {'❤️', '😂', '😍', '🔥', '👏', '😮', '😢', '🎉'}
    reaction = (request.get_json(silent=True) or {}).get('reaction', '')
    if reaction not in allowed_reactions:
        return jsonify({'error': 'Choose a supported reaction.'}), 400
    db = get_db()
    post = db.execute('SELECT user_id FROM posts WHERE id = ?', (post_id,)).fetchone()
    if post is None:
        return jsonify({'error': 'Post not found.'}), 404
    existing = db.execute(
        'SELECT reaction FROM post_reactions WHERE user_id = ? AND post_id = ?',
        (session['user_id'], post_id),
    ).fetchone()
    selected = ''
    if existing and existing['reaction'] == reaction:
        db.execute('DELETE FROM post_reactions WHERE user_id = ? AND post_id = ?', (session['user_id'], post_id))
    elif existing:
        db.execute(
            'UPDATE post_reactions SET reaction = ?, created_at = CURRENT_TIMESTAMP WHERE user_id = ? AND post_id = ?',
            (reaction, session['user_id'], post_id),
        )
        selected = reaction
    else:
        db.execute(
            'INSERT INTO post_reactions (user_id, post_id, reaction) VALUES (?, ?, ?)',
            (session['user_id'], post_id, reaction),
        )
        selected = reaction
    if selected:
        notify(post['user_id'], session['user_id'], 'reaction', f"{session.get('username', 'Someone')} reacted {reaction} to your post.", url_for('dashboard'))
    db.commit()
    rows = db.execute(
        'SELECT reaction, COUNT(*) AS total FROM post_reactions WHERE post_id = ? GROUP BY reaction',
        (post_id,),
    ).fetchall()
    counts = {row['reaction']: row['total'] for row in rows}
    return jsonify({'reaction': selected, 'counts': counts, 'total': sum(counts.values())})


@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    comment = request.form.get('comment', '').strip()
    if comment:
        db = get_db()
        db.execute(
            'INSERT INTO comments (post_id, user_id, body) VALUES (?, ?, ?)',
            (post_id, session['user_id'], comment),
        )
        db.commit()
        flash(f'Comment posted: {comment}', 'success')
    else:
        flash('Please write a comment before posting.', 'error')
    return redirect(url_for('dashboard'))


@app.route('/post/<int:post_id>/save', methods=['POST'])
@login_required
def toggle_saved_post(post_id):
    db = get_db()
    existing = db.execute(
        'SELECT 1 FROM saved_posts WHERE user_id = ? AND post_id = ?',
        (session['user_id'], post_id),
    ).fetchone()
    if existing:
        db.execute('DELETE FROM saved_posts WHERE user_id = ? AND post_id = ?', (session['user_id'], post_id))
        flash('Post removed from saved posts.', 'success')
    else:
        db.execute('INSERT INTO saved_posts (user_id, post_id) VALUES (?, ?)', (session['user_id'], post_id))
        flash('Post saved.', 'success')
    db.commit()
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/post/<int:post_id>/repost', methods=['POST'])
@login_required
def toggle_repost(post_id):
    db = get_db()
    post = db.execute('SELECT id, user_id FROM posts WHERE id = ?', (post_id,)).fetchone()
    if post is None:
        flash('Post not found.', 'error')
        return redirect(request.referrer or url_for('dashboard'))
    existing = db.execute(
        'SELECT 1 FROM reposts WHERE user_id = ? AND post_id = ?',
        (session['user_id'], post_id),
    ).fetchone()
    if existing:
        db.execute('DELETE FROM reposts WHERE user_id = ? AND post_id = ?', (session['user_id'], post_id))
        flash('Repost removed.', 'success')
    else:
        db.execute('INSERT INTO reposts (user_id, post_id) VALUES (?, ?)', (session['user_id'], post_id))
        notify(post['user_id'], session['user_id'], 'repost', f"{session.get('username', 'Someone')} reposted your post.", url_for('dashboard'))
        flash('Post reposted.', 'success')
    db.commit()
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/create-post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        caption = request.form.get('caption', '').strip()
        media = request.files.get('media') or request.files.get('camera_media')

        if not caption and not media:
            flash('Please add a caption or media.', 'error')
            return redirect(url_for('dashboard'))

        media_path = ''
        media_type = 'text'
        if media and media.filename:
            filename = secure_filename(media.filename)
            media_path = filename
            media_type = 'image' if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')) else 'video' if filename.lower().endswith(('.mp4', '.mov', '.avi', '.webm', '.mkv')) else 'file'
            file_path = UPLOAD_FOLDER / filename
            media.save(file_path)

        db = get_db()
        db.execute(
            'INSERT INTO posts (user_id, caption, media_path, media_type) VALUES (?, ?, ?, ?)',
            (session['user_id'], caption, media_path, media_type),
        )
        db.commit()
        flash('Post created successfully! Video uploads are capped at 10 minutes.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_post.html')


@app.route('/submit-data', methods=['POST'])
def submit_data():
    return 'This legacy data-submission endpoint is disabled. Use the account signup form.', 410


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = get_user_by_id(session['user_id'])
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip().lower()
        email = request.form.get('email', '').strip().lower()
        bio = request.form.get('bio', '').strip()
        phone = request.form.get('phone', '').strip()
        profile_picture = request.files.get('profile_picture')
        db = get_db()

        if not full_name:
            flash('Your full name is required.', 'error')
            return render_template('profile.html', user=user, posts=[])

        if not username:
            flash('A username is required.', 'error')
            return render_template('profile.html', user=user, posts=[])

        if not email:
            flash('An email address is required.', 'error')
            return render_template('profile.html', user=user, posts=[])

        if username != user['username']:
            existing = db.execute('SELECT id FROM users WHERE username = ? AND id != ?', (username, user['id'])).fetchone()
            if existing:
                flash('That username is already taken.', 'error')
                return render_template('profile.html', user=user, posts=[])

        if email != user['email']:
            existing = db.execute('SELECT id FROM users WHERE email = ? AND id != ?', (email, user['id'])).fetchone()
            if existing:
                flash('That email is already in use.', 'error')
                return render_template('profile.html', user=user, posts=[])

        profile_image = user['profile_picture']
        if profile_picture and profile_picture.filename:
            filename = secure_filename(profile_picture.filename)
            profile_image = filename
            profile_picture.save(UPLOAD_FOLDER / filename)

        db.execute(
            'UPDATE users SET full_name = ?, username = ?, email = ?, bio = ?, profile_picture = ?, phone = ? WHERE id = ?',
            (full_name, username, email, bio or user['bio'], profile_image, phone, user['id']),
        )
        db.commit()
        session['username'] = username
        flash('Profile updated!', 'success')
        user = get_user_by_id(session['user_id'])

    user_posts = get_db().execute(
        'SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],),
    ).fetchall()
    return render_template('profile.html', user=user, posts=user_posts)


@app.route('/admin')
@login_required
def admin():
    user = get_user_by_id(session['user_id'])
    if user is None or not user['is_admin']:
        session['is_admin'] = False
        flash('Access denied. Admin only.', 'error')
        return redirect(url_for('dashboard'))

    db = get_db()
    users = db.execute('SELECT id, full_name, username, email, is_admin FROM users ORDER BY id').fetchall()
    return render_template('admin.html', users=users)


def info_page(title, heading, content):
    return render_template_string('''
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{ title }}</title>
        <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
    </head>
    <body class="info-page">
        <div class="auth-container">
            <h1>{{ heading }}</h1>
            <p>{{ content|safe }}</p>
            <p><a href="{{ url_for('index') }}">Back home</a></p>
        </div>
    </body>
    </html>
    ''', title=title, heading=heading, content=content)


@app.route('/about')
def about():
    return info_page('About', 'About Zrydy', 'Zrydy is a simple social media app built for connecting people, sharing posts, and chatting in real time.')


@app.route('/contact')
def contact():
    return info_page('Contact', 'Contact Us', 'Phone: <a href="tel:08113373935">08113373935</a><br>Email: support@zrydy.com')


@app.route('/help')
def help_page():
    return info_page('Help', 'Help Center', 'Need support? Use the contact page or reach out to the admin team through the app.')


@app.route('/faq')
def faq_page():
    return info_page('FAQ', 'Frequently Asked Questions', 'Q: Can I upload photos and videos? A: Yes.<br>Q: Can I use my phone camera? A: Yes on supported mobile browsers.')


@app.route('/terms')
def terms_page():
    return info_page('Terms', 'Terms of Service', 'Use the app responsibly and keep your account information secure.')


@app.route('/privacy')
def privacy_page():
    return info_page('Privacy', 'Privacy Policy', 'We protect your information and only use it for app functionality and account access.')


@app.route('/support')
def support_page():
    return info_page('Support', 'Support', 'Phone: <a href="tel:08113373935">08113373935</a>')


@app.route('/feedback')
def feedback_page():
    return info_page('Feedback', 'Feedback', 'Tell us what you would like improved in the app.')


@app.route('/careers')
def careers_page():
    return info_page('Careers', 'Careers', 'We are growing. Check back soon for openings.')


@app.route('/press')
def press_page():
    return info_page('Press', 'Press', 'Zrydy is building a mobile-first social space.')


@app.route('/blog')
def blog_page():
    return info_page('Blog', 'Blog', 'Welcome to the Zrydy blog. Updates are coming soon.')


@app.route('/developers')
def developers_page():
    return info_page('Developers', 'Developers', 'Zrydy is designed to support mobile, messaging, posts, and camera features.')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


init_db()


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('FLASK_DEBUG') == '1',
    )
