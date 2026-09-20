import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, flash, g, jsonify, redirect, render_template, render_template_string, request, send_from_directory, session, url_for
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

app.config['DATABASE'] = os.environ.get('DATABASE_PATH', str(APP_DIR / 'social_media.db'))
app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL', '').strip()
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'local-development-secret-key')
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024
app.config['MAX_VIDEO_MINUTES'] = 10


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


@app.teardown_appcontext
def close_db(_exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


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
        '''CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), actor_id INTEGER REFERENCES users(id),
            kind TEXT NOT NULL, body TEXT NOT NULL, target_url TEXT DEFAULT '', is_read INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
    ]
    for statement in statements:
        db.execute(statement)
    db.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS media_path TEXT DEFAULT ''")
    db.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS media_type TEXT DEFAULT 'text'")
    db.execute('ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_read INTEGER NOT NULL DEFAULT 0')
    admin = db.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
    if admin is None:
        db.execute(
            'INSERT INTO users (full_name, username, email, password_hash, bio, profile_picture, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?)',
            ('System Admin', 'admin', 'admin@zrydy.com', generate_password_hash('admin123'), 'Welcome to Zrydy', '', 1),
        )
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
        db.execute('''CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, actor_id INTEGER,
            kind TEXT NOT NULL, body TEXT NOT NULL, target_url TEXT DEFAULT '',
            is_read INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        admin = db.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
        if admin is None:
            db.execute(
                'INSERT INTO users (full_name, username, email, password_hash, bio, profile_picture, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?)',
                ('System Admin', 'admin', 'admin@zrydy.com', generate_password_hash('admin123'), 'Welcome to Zrydy', '', 1),
            )
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
    return get_db().execute(
        'SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND is_read = 0',
        (session['user_id'],),
    ).fetchone()[0]


def get_unread_notification_count():
    if 'user_id' not in session:
        return 0
    return get_db().execute(
        'SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0',
        (session['user_id'],),
    ).fetchone()[0]


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
    blocked_clause = 'AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.blocker_id = ? AND b.blocked_id = p.user_id)'
    parameters = [query.strip(), search, search, search]
    if feed_mode == 'following':
        parameters.extend([user_id, user_id])
    parameters.append(user_id)
    rows = db.execute(
        '''
        SELECT p.*,
               u.username,
               u.full_name,
               u.profile_picture,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
        FROM posts p
        JOIN users u ON u.id = p.user_id
        WHERE (? = '' OR p.caption LIKE ? OR u.username LIKE ? OR u.full_name LIKE ?)
        {following_clause}
        {blocked_clause}
        ORDER BY p.created_at DESC
        '''.format(following_clause=following_clause, blocked_clause=blocked_clause),
        parameters,
    ).fetchall()
    return [dict(row) for row in rows]


def search_users(query):
    search = f'%{query.strip()}%'
    return get_db().execute(
        '''
        SELECT id, full_name, username, bio, profile_picture
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
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
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
        is_admin = db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0
        db.execute(
            'INSERT INTO users (full_name, username, email, password_hash, bio, profile_picture, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (full_name, username, email, generate_password_hash(password), 'New to Zrydy', '', 1 if is_admin else 0),
        )
        db.commit()

        user = get_user_by_username(username)
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = bool(user['is_admin'])
        flash('Registration successful!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not new_password:
            flash('Please enter a username and a new password.', 'error')
            return render_template('forgot_password.html')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('forgot_password.html')

        user = get_user_by_username(username)
        if not user:
            flash('User not found.', 'error')
            return render_template('forgot_password.html')

        db = get_db()
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (generate_password_hash(new_password), user['id']))
        db.commit()
        flash('Password updated successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


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
    if feed_mode not in {'for_you', 'following'}:
        feed_mode = 'for_you'
    posts = get_feed_posts(query, feed_mode)
    for post in posts:
        post['comments'] = get_comments_for_post(post['id'])
    people = search_users(query) if 'user_id' in session else []
    if 'user_id' in session:
        db = get_db()
        people = [dict(person) for person in people]
        for person in people:
            person['following'] = bool(db.execute('SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?', (session['user_id'], person['id'])).fetchone())
            person['blocked'] = bool(db.execute('SELECT 1 FROM blocks WHERE blocker_id = ? AND blocked_id = ?', (session['user_id'], person['id'])).fetchone())
    return render_template('dashboard.html', user=user, posts=posts, people=people, query=query, feed_mode=feed_mode)


@app.route('/live')
@login_required
def live():
    return render_template('live.html')


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
        body = request.form.get('body', '').strip()
        media = request.files.get('media')
        media_path = ''
        media_type = 'text'
        if media and media.filename:
            filename = secure_filename(media.filename)
            media_path = filename
            extension = Path(filename).suffix.lower()
            media_type = 'image' if extension in ('.png', '.jpg', '.jpeg', '.gif', '.webp') else 'video' if extension in ('.mp4', '.mov', '.webm', '.avi') else 'audio' if extension in ('.mp3', '.wav', '.ogg', '.m4a') else 'file'
            media.save(UPLOAD_FOLDER / filename)
        if body or media_path:
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
    name = request.form.get('name', '').strip()
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    user_input = request.form.get('user_input', '').strip()

    save_path = APP_DIR / 'users.txt'
    with save_path.open('a', encoding='utf-8') as f:
        f.write(f'{name}|{username}|{email}|{user_input}\n')

    return render_template('success.html', name=name, username=username, email=email, user_input=user_input)


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
    if not session.get('is_admin'):
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
    <body>
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


@app.route('/logout')
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
