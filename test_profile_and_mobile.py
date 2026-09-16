import pytest

from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_public_footer_links_and_media_access(client):
    response = client.get('/')
    html = response.get_data(as_text=True)
    assert '/about' in html
    assert '/contact' in html
    assert '/help' in html
    assert 'navigator.mediaDevices.getUserMedia' in html or 'mediaDevices' in html


def test_profile_allows_username_and_account_updates(client):
    client.post('/signup', data={
        'full_name': 'Jane Doe',
        'username': 'janedoe',
        'email': 'jane@example.com',
        'password': 'secret123',
        'confirm_password': 'secret123',
    }, follow_redirects=True)

    response = client.get('/profile')
    html = response.get_data(as_text=True)
    assert 'name="full_name"' in html
    assert 'name="username"' in html
    assert 'name="email"' in html
    assert 'name="bio"' in html

    update = client.post('/profile', data={
        'full_name': 'Jane Updated',
        'username': 'janeupdated',
        'email': 'janeupdated@example.com',
        'bio': 'New bio',
    }, follow_redirects=True)
    assert update.status_code == 200
    assert b'Profile updated' in update.data
