import pytest
import os, sys
from flask.testing import FlaskClient
pythonpath = os.environ['WORKSPACE'] + "/src"
sys.path.append(pythonpath)
from app import server, db


@pytest.fixture(scope='module')
def flask_app():
    app = server
    with app.app_context():
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['TESTING'] = True
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
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
        'submit': 'Login',
        'g-recaptcha-response': 'Test'
    })
    html = response.data.decode()   # Prints HTML that you are supposed to receive
    assert response.status_code == 200


def test_login_success(client):
    response = client.post('/login', data={
        'Email': os.environ['USER_TEST'],
        'password': os.environ['PWD_TEST'],
        'g-recaptcha-response': 'ILoveMyMama',
        'submit': 'Login'
    })
    html = response.data.decode()   # Prints HTML that you are supposed to receive
    assert response.status_code == 302  # Redirected, unless fail; 200


def test_register(client):
    response = client.post('/employees/insert', data={
        'FullName': 'JustTest Case',
        'Email': 'JustTestCase@gmail.com',
        'ContactNumber': '81234567',
        'DOB': '2000-01-01',
        'Role': 'driver',
        'Password': 'JustForTesting0124',
        'submit': 'Submit'
    })
    assert response.status_code == 302  # Redirected, unless fail; 200


def test_logout(client):
    response = client.get('/logout')
    html = response.data.decode()   # Prints HTML that you are supposed to receive
    assert response.status_code == 302  # Redirected, unless fail; 200


def test_reset_pass(client):
    response = client.post('/reset', data={
        'Phone': '81234567',
        'Email': '2000524@sit.singaporetech.edu.sg',
        'submit': 'Reset'
    })
    assert response.status_code == 200  # 200 even if user is not registered, to avoid brute forcing
