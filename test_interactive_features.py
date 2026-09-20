import io

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


def test_profile_picture_is_saved_and_rendered(client):
    signup(client, 'Picture User', 'pictureuser', 'picture@example.com')
    response = client.post(
        '/profile',
        data={
            'full_name': 'Picture User',
            'username': 'pictureuser',
            'email': 'picture@example.com',
            'bio': 'Has a picture',
            'profile_picture': (io.BytesIO(b'fake-image'), 'avatar.jpg'),
        },
        content_type='multipart/form-data',
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b'avatar.jpg' in response.data
    assert b'profile-image' in response.data


def test_unread_notification_and_media_message(client):
    signup(client, 'Sender User', 'sender', 'sender@example.com')
    client.get('/logout')
    signup(client, 'Receiver User', 'receiver', 'receiver@example.com')
    client.get('/logout')
    client.post('/login', data={'username': 'sender', 'password': 'secret123'})

    response = client.post(
        '/messages/3',
        data={'body': 'Photo for you', 'media': (io.BytesIO(b'image-bytes'), 'photo.jpg')},
        content_type='multipart/form-data',
        follow_redirects=True,
    )
    assert response.status_code == 200

    client.get('/logout')
    client.post('/login', data={'username': 'receiver', 'password': 'secret123'})
    notification = client.get('/notifications')
    assert notification.status_code == 200
    assert notification.json['count'] == 1
    chat = client.get('/messages/2')
    assert b'Photo for you' in chat.data
    assert b'photo.jpg' in chat.data


def test_follow_notification_feed_modes_and_block(client):
    signup(client, 'Creator User', 'creator', 'creator@example.com')
    client.post('/create-post', data={'caption': 'Creator only post'}, follow_redirects=True)
    client.get('/logout')
    signup(client, 'Follower User', 'follower', 'follower@example.com')

    follow = client.post('/user/2/follow', follow_redirects=True)
    assert follow.status_code == 200
    client.get('/logout')
    client.post('/login', data={'username': 'creator', 'password': 'secret123'})
    alerts = client.get('/notifications').json
    assert alerts['count'] == 1
    assert 'following' in alerts['notifications'][0]['body']

    client.get('/logout')
    client.post('/login', data={'username': 'follower', 'password': 'secret123'})
    following = client.get('/dashboard?feed=following')
    assert b'Creator only post' in following.data

    blocked = client.post('/user/2/block', follow_redirects=True)
    assert blocked.status_code == 200
    following_after_block = client.get('/dashboard?feed=following')
    assert b'Creator only post' not in following_after_block.data


def test_conversation_can_be_deleted(client):
    signup(client, 'First User', 'first', 'first@example.com')
    client.get('/logout')
    signup(client, 'Second User', 'second', 'second@example.com')
    client.post('/messages/2', data={'body': 'Remove this chat'}, follow_redirects=True)
    deleted = client.post('/messages/2/delete', follow_redirects=True)
    assert deleted.status_code == 200
    assert b'Remove this chat' not in deleted.data
