import io
import re

import pytest

from app import app


@pytest.fixture
def client(tmp_path):
    app.config['TESTING'] = True
    app.config['DATABASE'] = str(tmp_path / 'users.db')
    app.config['SECRET_KEY'] = 'test-secret-key'
    from app import init_db
    init_db()
    with app.test_client() as client:
        yield client


def test_signup_and_login_flow(client):
    signup = client.post(
        '/signup',
        data={
            'full_name': 'Jane Doe',
            'username': 'janedoe',
            'email': 'jane@example.com',
            'password': 'secret123',
            'confirm_password': 'secret123',
        },
        follow_redirects=True,
    )

    assert signup.status_code == 200
    assert b'dashboard' in signup.data.lower()

    client.post('/logout')

    login = client.post(
        '/login',
        data={
            'username': 'janedoe',
            'password': 'secret123',
        },
        follow_redirects=True,
    )

    assert login.status_code == 200
    assert b'dashboard' in login.data.lower()


def test_logout_then_login_accepts_username_case(client):
    client.post(
        '/signup',
        data={
            'full_name': 'Case User',
            'username': 'caseuser',
            'email': 'case@example.com',
            'password': 'secret123',
            'confirm_password': 'secret123',
        },
        follow_redirects=True,
    )
    logout = client.post('/logout')
    assert logout.status_code == 302

    login = client.post(
        '/login',
        data={'username': 'CaseUser', 'password': 'secret123'},
        follow_redirects=True,
    )
    assert login.status_code == 200
    assert b'dashboard' in login.data.lower()


def test_stale_session_redirects_to_login_instead_of_server_error(client):
    with client.session_transaction() as session:
        session['user_id'] = 999999
        session['username'] = 'deleted-user'

    response = client.get('/dashboard', follow_redirects=True)
    assert response.status_code == 200
    assert b'session expired' in response.data.lower()


def test_admin_can_view_users_only_after_explicit_bootstrap(client, monkeypatch):
    monkeypatch.setenv('BOOTSTRAP_ADMIN_USERNAME', 'secureadmin')
    monkeypatch.setenv('BOOTSTRAP_ADMIN_EMAIL', 'secureadmin@example.com')
    monkeypatch.setenv('BOOTSTRAP_ADMIN_PASSWORD', 'test-only-bootstrap-password-2026')
    from app import init_db
    init_db()
    login = client.post(
        '/login',
        data={
            'username': 'secureadmin',
            'password': 'test-only-bootstrap-password-2026',
        },
        follow_redirects=True,
    )

    assert login.status_code == 200
    response = client.get('/admin')
    assert response.status_code == 200
    assert b'Admin' in response.data or b'admin' in response.data.lower()


def test_profile_page_shows_user_data(client):
    client.post('/signup', data={
        'full_name': 'Profile User',
        'username': 'profileuser',
        'email': 'profile@example.com',
        'password': 'profilepass123',
        'confirm_password': 'profilepass123',
    }, follow_redirects=True)

    response = client.get('/profile')
    assert response.status_code == 200
    assert b'Profile' in response.data
    assert b'admin' in response.data.lower()


def test_forgot_password_cannot_reset_password_by_username(client):
    client.post(
        '/signup',
        data={
            'full_name': 'Reset User',
            'username': 'resetuser',
            'email': 'reset@example.com',
            'password': 'oldpass',
            'confirm_password': 'oldpass',
        },
        follow_redirects=True,
    )

    reset = client.post(
        '/forgot-password',
        data={
            'username': 'resetuser',
            'new_password': 'newpass123',
            'confirm_password': 'newpass123',
        },
        follow_redirects=True,
    )

    assert reset.status_code == 200
    assert b'verified email' in reset.data.lower()

    logout = client.post('/logout')
    assert logout.status_code == 302

    login = client.post(
        '/login',
        data={
            'username': 'resetuser',
            'password': 'oldpass',
        },
        follow_redirects=True,
    )

    assert login.status_code == 200
    assert b'dashboard' in login.data.lower()


def test_password_change_requires_current_password(client):
    client.post('/signup', data={
        'full_name': 'Password User',
        'username': 'passworduser',
        'email': 'password@example.com',
        'password': 'old-password-123',
        'confirm_password': 'old-password-123',
    })
    rejected = client.post('/change-password', data={
        'current_password': 'wrong-password',
        'new_password': 'new-password-1234',
        'confirm_password': 'new-password-1234',
    }, follow_redirects=True)
    assert b'Current password is incorrect.' in rejected.data

    changed = client.post('/change-password', data={
        'current_password': 'old-password-123',
        'new_password': 'new-password-1234',
        'confirm_password': 'new-password-1234',
    }, follow_redirects=True)
    assert b'Password changed successfully.' in changed.data

    client.post('/logout')
    login = client.post('/login', data={
        'username': 'passworduser',
        'password': 'new-password-1234',
    }, follow_redirects=True)
    assert login.status_code == 200
    assert b'dashboard' in login.data.lower()


def test_csrf_rejects_missing_tokens_and_accepts_valid_form_token(client):
    login_page = client.get('/login')
    match = re.search(rb'name="csrf_token" value="([^"]+)"', login_page.data)
    assert match
    token = match.group(1).decode()
    app.config['TESTING'] = False
    try:
        rejected = client.post('/login', data={'username': 'missing', 'password': 'wrong'})
        accepted = client.post('/login', data={
            'username': 'missing',
            'password': 'wrong',
            'csrf_token': token,
        })
        assert rejected.status_code == 400
        assert accepted.status_code == 200
    finally:
        app.config['TESTING'] = True


def test_user_can_create_post_in_feed(client):
    client.post(
        '/signup',
        data={
            'full_name': 'Social User',
            'username': 'socialuser',
            'email': 'social@example.com',
            'password': 'socialpass',
            'confirm_password': 'socialpass',
        },
        follow_redirects=True,
    )

    image = (io.BytesIO(b'fake-image-bytes'), 'profile.jpg')
    response = client.post(
        '/create-post',
        data={
            'caption': 'A new social post',
            'media': image,
        },
        content_type='multipart/form-data',
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b'A new social post' in response.data
    assert b'profile.jpg' in response.data or b'uploaded' in response.data.lower()
