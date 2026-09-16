import io

from app import app


def test_like_and_comment_are_supported():
    client = app.test_client()
    client.post(
        '/signup',
        data={
            'full_name': 'Tester User',
            'username': 'tester',
            'email': 'tester@example.com',
            'password': 'secret123',
            'confirm_password': 'secret123',
        },
        follow_redirects=True,
    )

    client.post(
        '/create-post',
        data={'caption': 'Hello world'},
        follow_redirects=True,
    )

    like_response = client.post('/post/1/like', follow_redirects=True)
    assert like_response.status_code == 200
    assert b'like' in like_response.data.lower()

    comment_response = client.post('/post/1/comment', data={'comment': 'Nice post!'}, follow_redirects=True)
    assert comment_response.status_code == 200
    assert b'Nice post!' in comment_response.data


def test_dashboard_mentions_share_and_video_duration_limit():
    client = app.test_client()
    response = client.get('/dashboard')
    assert response.status_code == 200
    html = response.get_data(as_text=True).lower()
    assert 'share' in html
    assert '10 minutes' in html or '10-minute' in html
    assert 'navigator.share' in html or 'share via' in html
