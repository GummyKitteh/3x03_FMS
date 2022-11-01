import pytest
from flask.testing import FlaskClient
from src.app import server, db

@pytest.fixture(scope='module')
def flask_app():
    app = server
    with app.app_context():
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['TESTING'] = True
        yield app


@pytest.fixture(scope='module')
def client(flask_app):
    app = flask_app
    ctx = flask_app.test_request_context()
    ctx.push()
    app.test_client_class = FlaskClient
    return app.test_client()


def test_index_page(client):
    res = client.get('/')
    assert res.status_code == 200


def test_login_page(client):
    res = client.get('/login')
    assert res.status_code == 200


def test_login_failure(client):
    response = client.post('/login', data={
        'Email': 'wrong@gmail.com',
        'password': 'wrongPass',
        'submit': 'Login'
    })
    assert response.status_code == 200


def test_login_success(client):
    response = client.post('/login', data={
        'Email': 'b33p33p@gmail.com',
        'password': 'admin@123',
        'submit': 'Login'
    })
    assert response.status_code == 302


def test_logout(client):
    response = client.get('/logout')
    assert response.status_code == 302


