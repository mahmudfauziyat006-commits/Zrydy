import pytest

from app import app


@pytest.fixture
def client(tmp_path):
    app.config['TESTING'] = True
    app.config['DATABASE'] = str(tmp_path / 'interactive.db')
    with app.test_client() as client:
        from app import init_db
        init_db()
        yield client


def signup(client, full_name, username, email):
    return client.post('/signup', data={
        'full_name': full_name,
        'username': username,
        'email': email,
        'password': 'secret123',
        'confirm_password': 'secret123',
    }, follow_redirects=True)


def test_search_finds_people_and_posts(client):
    signup(client, 'Jane Doe', 'janedoe', 'jane@example.com')
    client.post('/create-post', data={'caption': 'Jane community post'}, follow_redirects=True)
    client.get('/logout')
    signup(client, 'John Smith', 'johnsmith', 'john@example.com')

    response = client.get('/dashboard?q=Jane')
    assert response.status_code == 200
    assert b'Jane Doe' in response.data
    assert b'Jane community post' in response.data
    assert b'/messages/' in response.data


def test_user_can_create_and_use_group_chat(client):
    signup(client, 'Owner User', 'owner', 'owner@example.com')
    client.get('/logout')
    signup(client, 'Member User', 'member', 'member@example.com')

    messages = client.get('/messages')
    assert b'Create a group chat' in messages.data
    group = client.post('/groups/create', data={
        'name': 'Project Team',
        'member_ids': ['1'],
    }, follow_redirects=True)
    assert group.status_code == 200
    assert b'Project Team' in group.data

    response = client.post('/groups/1', data={'body': 'Hello team'}, follow_redirects=True)
    assert response.status_code == 200
    assert b'Hello team' in response.data
