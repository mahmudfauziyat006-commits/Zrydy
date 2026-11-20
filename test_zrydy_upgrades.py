import pytest

from app import app, init_db


@pytest.fixture
def client(tmp_path):
    app.config['TESTING'] = True
    app.config['DATABASE'] = str(tmp_path / 'zrydy.db')
    app.config['SECRET_KEY'] = 'test-secret-key'
    init_db()
    with app.test_client() as test_client:
        yield test_client


def login(client, username='zrydyuser'):
    client.post('/signup', data={
        'full_name': 'Zrydy User',
        'username': username,
        'email': f'{username}@example.com',
        'password': 'secure-password-2026',
        'confirm_password': 'secure-password-2026',
    }, follow_redirects=True)


def test_profile_presence_privacy_and_quiet_mode(client):
    login(client)
    response = client.post('/profile', data={
        'full_name': 'Zrydy User',
        'username': 'zrydyuser',
        'email': 'zrydyuser@example.com',
        'bio': 'Building with intention',
        'phone': '+2348000000000',
        'interests': 'Design, music',
        'links': 'https://example.com/zrydy',
        'presence_state': 'Open to Link',
        'privacy_default': 'circle',
        'notification_preferences': 'essential',
        'quiet_mode': 'on',
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Profile updated' in response.data

    with app.app_context():
        from app import get_db
        user = get_db().execute('SELECT * FROM users WHERE username = ?', ('zrydyuser',)).fetchone()
        assert user['presence_state'] == 'Open to Link'
        assert user['privacy_default'] == 'circle'
        assert user['quiet_mode'] == 1


def test_pulse_can_be_published_and_opened(client):
    login(client)
    response = client.post('/pulses', data={
        'body': 'Looking for a design collaborator',
        'topic': 'Design',
        'zone': 'Lagos',
        'duration': '2',
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Looking for a design collaborator' in response.data

    feed = client.get('/dashboard?feed=live_radar')
    assert feed.status_code == 200


def test_living_drop_and_report_paths_are_real(client):
    login(client)
    post_response = client.post('/create-post', data={
        'caption': 'Shipping Zrydy v2',
        'living_drop': 'on',
        'privacy': 'public',
    }, follow_redirects=True)
    assert post_response.status_code == 200

    with app.app_context():
        from app import get_db
        post = get_db().execute('SELECT id, is_living_drop FROM posts WHERE caption = ?', ('Shipping Zrydy v2',)).fetchone()
        assert post is not None
        assert post['is_living_drop'] == 1
