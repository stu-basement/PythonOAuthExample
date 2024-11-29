"""Test Meta/Facebook OAuth functionality."""
from unittest.mock import patch, Mock, ANY
from http import HTTPStatus

import os
import pytest
from flask_login import LoginManager

from app import create_app, AuthProvider

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


def test_meta_callback_missing_code(sso_client):
    """Test callback handling when authorization code is missing."""
    response = sso_client.get('/login/meta/callback')
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert b'Authorization code not received' in response.data


@patch('requests.get')
@patch('requests.post')
def test_meta_callback_token_error(mock_post, mock_get, sso_client):
    """Test handling of token exchange error."""
    mock_provider_config = {
        "token_endpoint": "https://graph.facebook.com/v18.0/oauth/access_token",
        "userinfo_endpoint": "https://graph.facebook.com/v18.0/me"
    }

    discovery_response = Mock()
    discovery_response.json = lambda: mock_provider_config
    discovery_response.ok = True

    token_response = Mock()
    token_response.ok = False
    token_response.status_code = HTTPStatus.UNAUTHORIZED

    mock_get.return_value = discovery_response
    mock_post.return_value = token_response

    response = sso_client.get('/login/meta/callback?code=dummy_code')
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert b'Failed to get user info' in response.data


@patch('requests.get')
@patch('requests.post')
def test_meta_callback_userinfo_error(mock_post, mock_get, sso_client):
    """Test handling of userinfo endpoint error."""
    mock_provider_config = {
        "token_endpoint": "https://graph.facebook.com/v18.0/oauth/access_token",
        "userinfo_endpoint": "https://graph.facebook.com/v18.0/me"
    }

    discovery_response = Mock()
    discovery_response.json = lambda: mock_provider_config
    discovery_response.ok = True

    userinfo_response = Mock()
    userinfo_response.ok = False
    userinfo_response.status_code = HTTPStatus.UNAUTHORIZED

    token_response = Mock()
    token_response.json = lambda: {
        "access_token": "dummy_token",
        "token_type": "Bearer"
    }
    token_response.ok = True

    mock_post.return_value = token_response
    mock_get.side_effect = lambda url, **kwargs: \
        discovery_response if 'oauth' in url else userinfo_response

    response = sso_client.get('/login/meta/callback?code=dummy_code')
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert b'Failed to get user info' in response.data


@patch('requests.get')
@patch('requests.post')
def test_meta_callback_missing_email(mock_post, mock_get, sso_client):
    """Test handling of userinfo response missing required fields."""
    mock_provider_config = {
        "token_endpoint": "https://graph.facebook.com/v18.0/oauth/access_token",
        "userinfo_endpoint": "https://graph.facebook.com/v18.0/me"
    }

    def get_side_effect(*args):
        mock_response = Mock()
        if 'oauth' in args[0]:
            mock_response.json = lambda: mock_provider_config
            mock_response.ok = True
        elif 'me' in args[0]:
            mock_response.json = lambda: {
                "id": "12345",
                "name": "Test User",
                "picture": {
                    "data": {
                        "url": "https://example.com/pic.jpg"
                    }
                }
            }  # Missing email field
            mock_response.ok = True
        mock_response.raise_for_status = Mock()
        return mock_response

    mock_get.side_effect = get_side_effect

    token_response = Mock()
    token_response.json = lambda: {
        "access_token": "dummy_token",
        "token_type": "Bearer"
    }
    token_response.ok = True
    mock_post.return_value = token_response

    response = sso_client.get('/login/meta/callback?code=dummy_code')
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert b'Authentication failed' in response.data


def test_meta_callback_invalid_provider(sso_client):
    """Test callback with invalid provider."""
    response = sso_client.get('/login/invalid_provider/callback?code=dummy_code')
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert b'Unsupported authentication provider' in response.data


@patch('requests.get')
@patch('requests.post')
def test_meta_callback_success(mock_post, mock_get, sso_client):
    """Test successful Meta callback handling."""
    # Mock user info response
    mock_user_info = {
        "id": "12345",
        "name": "Test User",
        "email": "test@example.com",
        "picture": {
            "data": {
                "url": "https://example.com/pic.jpg"
            }
        }
    }

    # Mock the OAuth provider configuration
    mock_provider_config = {
        "token_endpoint": "https://graph.facebook.com/v18.0/oauth/access_token",
        "userinfo_endpoint": "https://graph.facebook.com/v18.0/me"
    }

    with patch('app.User.get', return_value=None), \
         patch('app.User.create') as mock_create, \
         patch('app.login_user') as mock_login:

        discovery_response = Mock()
        discovery_response.json = lambda: mock_provider_config
        discovery_response.ok = True

        userinfo_response = Mock()
        userinfo_response.json = lambda: mock_user_info
        userinfo_response.ok = True

        token_response = Mock()
        token_response.json = lambda: {
            "access_token": "dummy_token",
            "token_type": "Bearer"
        }
        token_response.ok = True
        mock_post.return_value = token_response

        mock_get.side_effect = lambda url, **kwargs: \
            discovery_response if 'oauth' in url else userinfo_response

        response = sso_client.get('/login/meta/callback?code=dummy_code')

        assert response.status_code == HTTPStatus.FOUND
        assert mock_create.called
        mock_create.assert_called_with(
            mock_user_info["id"],
            "META",
            mock_user_info["name"],
            mock_user_info["email"],
            mock_user_info["picture"]["data"]["url"]
        )
        assert mock_login.called


@patch('requests.get')
@patch('requests.post')
def test_existing_meta_user_login(mock_post, mock_get, sso_client):
    """Test successful login for existing Meta user."""
    mock_user_info = {
        "id": "12345",
        "name": "Test User",
        "email": "test@example.com",
        "picture": {
            "data": {
                "url": "https://example.com/pic.jpg"
            }
        }
    }

    mock_existing_user = Mock()
    mock_existing_user.id = mock_user_info["id"]
    mock_existing_user.name = mock_user_info["name"]
    mock_existing_user.email = mock_user_info["email"]
    mock_existing_user.profile_pic = mock_user_info["picture"]["data"]["url"]
    mock_existing_user.provider = "META"

    with patch('app.User.get', return_value=mock_existing_user), \
         patch('app.User.create') as mock_create, \
         patch('app.login_user') as mock_login:

        discovery_response = Mock()
        discovery_response.json = lambda: {
            "token_endpoint": "https://graph.facebook.com/v18.0/oauth/access_token",
            "userinfo_endpoint": "https://graph.facebook.com/v18.0/me"
        }
        discovery_response.ok = True

        userinfo_response = Mock()
        userinfo_response.json = lambda: mock_user_info
        userinfo_response.ok = True

        token_response = Mock()
        token_response.json = lambda: {
            "access_token": "dummy_token",
            "token_type": "Bearer"
        }
        token_response.ok = True
        mock_post.return_value = token_response

        mock_get.side_effect = lambda url, **kwargs: \
            discovery_response if 'oauth' in url else userinfo_response

        response = sso_client.get('/login/meta/callback?code=dummy_code')

        assert response.status_code == HTTPStatus.FOUND
        assert not mock_create.called
        assert mock_login.called
        mock_login.assert_called_with(ANY)

        actual_user = mock_login.call_args[0][0]
        assert actual_user.id == mock_existing_user.id
        assert actual_user.name == mock_existing_user.name
        assert actual_user.email == mock_existing_user.email
        assert actual_user.profile_pic == mock_existing_user.profile_pic
        assert actual_user.provider == mock_existing_user.provider


@patch('requests.get')
@patch('requests.post')
def test_multiple_meta_logins_same_user(mock_post, mock_get, sso_client):
    """Test user can log in multiple times with Meta."""
    mock_user_info = {
        "id": "12345",
        "name": "Test User",
        "email": "test@example.com",
        "picture": {
            "data": {
                "url": "https://example.com/pic.jpg"
            }
        }
    }

    mock_existing_user = Mock()
    mock_existing_user.id = mock_user_info["id"]
    mock_existing_user.name = mock_user_info["name"]
    mock_existing_user.email = mock_user_info["email"]
    mock_existing_user.profile_pic = mock_user_info["picture"]["data"]["url"]
    mock_existing_user.provider = "META"

    with patch('app.User.get', return_value=mock_existing_user), \
         patch('app.User.create'):

        discovery_response = Mock()
        discovery_response.json = lambda: {
            "token_endpoint": "https://graph.facebook.com/v18.0/oauth/access_token",
            "userinfo_endpoint": "https://graph.facebook.com/v18.0/me"
        }
        discovery_response.ok = True

        userinfo_response = Mock()
        userinfo_response.json = lambda: mock_user_info
        userinfo_response.ok = True

        token_response = Mock()
        token_response.json = lambda: {
            "access_token": "dummy_token",
            "token_type": "Bearer"
        }
        token_response.ok = True
        mock_post.return_value = token_response

        mock_get.side_effect = lambda url, **kwargs: \
            discovery_response if 'oauth' in url else userinfo_response

        # First login
        response1 = sso_client.get('/login/meta/callback?code=dummy_code1')
        assert response1.status_code == HTTPStatus.FOUND

        # Logout
        with patch('app.logout_user'):
            sso_client.get('/logout')

        # Second login
        response2 = sso_client.get('/login/meta/callback?code=dummy_code2')
        assert response2.status_code == HTTPStatus.FOUND


def test_auth_provider_enum():
    """Test AuthProvider enum configuration for Meta."""
    assert AuthProvider.META.discovery_url == \
        "https://www.facebook.com/.well-known/openid-configuration"
    assert "email" in AuthProvider.META.required_scopes()
    assert "public_profile" in AuthProvider.META.required_scopes()
    assert AuthProvider.META.client_id_env_var == "META_CLIENT_ID"
