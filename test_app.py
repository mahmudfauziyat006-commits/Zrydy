from app import app


def test_legacy_submit_data_endpoint_is_disabled():
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

    assert response.status_code == 410
    assert b'disabled' in response.data.lower()
