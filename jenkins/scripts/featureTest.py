import pytest
import os, sys
from flask.testing import FlaskClient
#sys.path.append(os.environ['WORKSPACE'])
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
    html = response.data.decode()   # Prints HTML that you are supposed to receive
    assert response.status_code == 200


def test_login_success(client):
    response = client.post('/login', data={
        'Email': 'b33p33p@gmail.com',
        'password': 'admin@123',
        'submit': 'Login'
    })
    html = response.data.decode()   # Prints HTML that you are supposed to receive
    assert response.status_code == 302


def test_register(client):
    response = client.post('/employees/insert', data={
        'FullName': 'Just Test',
        'Email': 'JustTest@gmail.com',
        'ContactNumber': '81234567',
        'DOB': '2000-01-01',
        'Role': 'driver',
        'Password': 'JustForTesting',
        'submit': 'Submit'
    })
    assert response.status_code == 302


def test_logout(client):
    response = client.get('/logout')
    html = response.data.decode()   # Prints HTML that you are supposed to receive
    assert response.status_code == 302


def test_reset_pass(client):
    response = client.post('/reset', data={
        'Phone': '81234567',
        'Email': '2000524@sit.singaporetech.edu.sg',
        'submit': 'Reset'
    })
    assert response.status_code == 200
