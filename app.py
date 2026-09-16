import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, render_template_string, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
APP_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = APP_DIR / 'uploads'
UPLOAD_FOLDER.mkdir(exist_ok=True)

app.config['DATABASE'] = str(APP_DIR / 'social_media.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'local-development-secret-key')
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['MAX_VIDEO_MINUTES'] = 3


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        g._database = db
    return db


@app.teardown_appcontext
def close_db(_exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
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
                is_admin INTEGER NOT NULL DEFAULT 0
            )
            '''
        )
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

        admin = db.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
        if admin is None:
            db.execute(
                'INSERT INTO users (full_name, username, email, password_hash, bio, profile_picture, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?)',
                ('System Admin', 'admin', 'admin@zrydy.com', generate_password_hash('admin123'), 'Welcome to Zrydy', '', 1),
            )
        db.commit()


def get_user_by_username(username):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()


def get_user_by_id(user_id):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()


def get_all_users():
    db = get_db()
    return db.execute(
        'SELECT id, full_name, username, profile_picture FROM users WHERE id != ? ORDER BY username',
        (session['user_id'],),
    ).fetchall()


def get_feed_posts():
    db = get_db()
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
        ORDER BY p.created_at DESC
        '''
    ).fetchall()
    return [dict(row) for row in rows]


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
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(*args, **kwargs)

    return wrapped_view


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
        username = request.form.get('username', '').strip()
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
    else:
        user = {
            'full_name': 'Guest User',
            'username': 'guest',
            'bio': 'Welcome to Zrydy.',
            'profile_picture': '',
        }
    posts = get_feed_posts()
    for post in posts:
        post['comments'] = get_comments_for_post(post['id'])
    return render_template('dashboard.html', user=user, posts=posts)


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
    return render_template('messages.html', conversations=conversations, users=get_all_users())


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
        if body:
            db.execute(
                'INSERT INTO messages (sender_id, recipient_id, body) VALUES (?, ?, ?)',
                (session['user_id'], user_id, body),
            )
            db.commit()
        return redirect(url_for('conversation', user_id=user_id))

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
        flash('Post created successfully! Video uploads are capped at 3 minutes.', 'success')
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
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        bio = request.form.get('bio', '').strip()
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
            'UPDATE users SET full_name = ?, username = ?, email = ?, bio = ?, profile_picture = ? WHERE id = ?',
            (full_name, username, email, bio or user['bio'], profile_image, user['id']),
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
