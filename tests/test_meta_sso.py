"""Test Meta/Facebook OAuth functionality."""
from unittest.mock import patch, Mock
from http import HTTPStatus

import os
import pytest
from flask_login import LoginManager

from app import create_app


@pytest.fixture(name="sso_client")
def fixture_sso_client(sso_app):
    """Create test client."""
    return sso_app.test_client()


@pytest.fixture(name="mock_meta_config")
def fixture_mock_meta_config():
    """Create mock Meta OAuth configuration."""
    return {
        "authorization_endpoint": "https://facebook.com/v18.0/dialog/oauth",
        "token_endpoint": "https://graph.facebook.com/v18.0/oauth/access_token",
        "userinfo_endpoint": "https://graph.facebook.com/v18.0/me"
    }


@pytest.fixture(name="sso_app")
def fixture_sso_app():
    """Create application for the tests."""
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    sso_app = create_app({
        'TESTING': True,
        'SECRET_KEY': 'test_secret_key',
        'META_CLIENT_ID': 'test_client_id',
        'META_CLIENT_SECRET': 'test_client_secret'
    })

    login_manager = LoginManager()
    login_manager.init_app(sso_app)

    @login_manager.user_loader
    def load_user(user_id):  # pylint: disable=missing-docstring
        return Mock(
            id=user_id,
            is_authenticated=True,
            is_active=True,
            email="test@example.com"
        )

    return sso_app


def test_meta_login_button_present(sso_client):
    """Test that Meta login button appears on index page."""
    response = sso_client.get('/')
    assert response.status_code == HTTPStatus.OK
    assert b'href="/login/meta"' in response.data


def test_meta_login_redirect(sso_client, mock_meta_config):
    """Test that /login/meta redirects to Meta's auth endpoint."""
    with patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = mock_meta_config
        mock_get.return_value.ok = True

        response = sso_client.get('/login/meta')
        assert response.status_code == HTTPStatus.FOUND
        assert 'facebook.com' in response.headers['Location']
        assert 'email' in response.headers['Location']
        assert 'public_profile' in response.headers['Location']


def test_meta_login_missing_client_id(sso_client, sso_app):
    """Test handling of missing Meta client ID."""
    sso_app.config['META_CLIENT_ID'] = None
    response = sso_client.get('/login/meta')
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert b'Client ID not configured' in response.data 
