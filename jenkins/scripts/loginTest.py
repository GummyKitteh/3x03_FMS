import pytest
from flask.testing import FlaskClient
from src.app import server, db


@pytest.fixture(scope='module')
def flask_app():
    app = server
    with app.app_context():
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


#def test_login_page(client):
