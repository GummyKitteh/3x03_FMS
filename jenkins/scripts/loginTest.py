import pytest

from src.app import server, db


@pytest.fixture()
def app():
    app = server()
    app.config.update({
        "TESTING": True,
    })
    # other setup go here

    yield app

    # clean up / reset resources here


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()


def test_index_page_logged_in(client):
    res = client.get('/')
    assert res.status_code == 200
