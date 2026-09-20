import io

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

    client.get('/logout')

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
    logout = client.get('/logout')
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


def test_admin_can_view_users(client):
    login = client.post(
        '/login',
        data={
            'username': 'admin',
            'password': 'admin123',
        },
        follow_redirects=True,
    )

    assert login.status_code == 200
    response = client.get('/admin')
    assert response.status_code == 200
    assert b'Admin' in response.data or b'admin' in response.data.lower()


def test_profile_page_shows_user_data(client):
    client.post(
        '/login',
        data={
            'username': 'admin',
            'password': 'admin123',
        },
        follow_redirects=True,
    )

    response = client.get('/profile')
    assert response.status_code == 200
    assert b'Profile' in response.data
    assert b'admin' in response.data.lower()


def test_forgot_password_updates_password(client):
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
    assert b'Password updated successfully' in reset.data

    logout = client.get('/logout')
    assert logout.status_code == 302

    login = client.post(
        '/login',
        data={
            'username': 'resetuser',
            'password': 'newpass123',
        },
        follow_redirects=True,
    )

    assert login.status_code == 200
    assert b'dashboard' in login.data.lower()


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
