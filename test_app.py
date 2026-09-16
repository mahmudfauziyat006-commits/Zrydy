from pathlib import Path

from app import APP_DIR, app


def test_submit_data_saves_and_shows_success(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    client = app.test_client()

    response = client.post(
        '/submit-data',
        data={
            'name': 'Jane Doe',
            'username': 'janedoe',
            'email': 'jane@example.com',
            'user_input': 'Welcome'
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b'Account created successfully' in response.data

    saved = (APP_DIR / 'users.txt').read_text(encoding='utf-8')
    assert 'janedoe' in saved
    assert 'Jane Doe' in saved
