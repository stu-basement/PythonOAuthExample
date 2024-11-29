''' Test Google OAuth functionality '''
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

@pytest.fixture(name="mock_google_config")
def fixture_mock_google_config():
    '''Create mock Google OAuth configuration.'''
    return {
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v2/userinfo"
    }

@pytest.fixture(name="sso_app")
def fixture_sso_app():
    """Create application for the tests."""
    # Allow OAuth without HTTPS in testing
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    sso_app = create_app({
        'TESTING': True,
        'SECRET_KEY': 'test_secret_key',
        'GOOGLE_CLIENT_ID': 'test_client_id',
        'GOOGLE_CLIENT_SECRET': 'test_client_secret'
    })

    # Set up login manager for testing
    login_manager = LoginManager()
    login_manager.init_app(sso_app)

    @login_manager.user_loader
    def load_user(user_id):
        return Mock(
            id=user_id,
            is_authenticated=True,
            is_active=True,
            email="test@example.com"
        )

    return sso_app

def test_google_login_button_present(sso_client):
    """Test that Google login button appears on index page."""
    response = sso_client.get('/')
    assert response.status_code == HTTPStatus.OK
    assert b'href="/login/google"' in response.data

def test_google_login_redirect(sso_client, mock_google_config):
    """Test that /login/google redirects to Google's auth endpoint."""
    with patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = mock_google_config
        mock_get.return_value.ok = True

        response = sso_client.get('/login/google')
        assert response.status_code == HTTPStatus.FOUND  # 302 redirect
        assert 'accounts.google.com' in response.headers['Location']
        assert 'openid' in response.headers['Location']
        assert 'email' in response.headers['Location']
        assert 'profile' in response.headers['Location']

def test_google_login_missing_client_id(sso_client, sso_app):
    """Test handling of missing Google client ID."""
    sso_app.config['GOOGLE_CLIENT_ID'] = None
    response = sso_client.get('/login/google')
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert b'Client ID not configured' in response.data

@patch('requests.get')
@patch('requests.post')
def test_google_callback_success(mock_post, mock_get, sso_client):
    """Test successful Google callback handling."""
    # Mock user info response
    mock_user_info = {
        "sub": "12345",
        "provider": "GOOGLE",
        "given_name": "Test User",
        "email": "test@example.com",
        "picture": "https://example.com/pic.jpg"
    }

    # Mock the OAuth provider configuration
    mock_provider_config = {
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v2/userinfo"
    }

    with patch('app.User.get', return_value=None), \
         patch('app.User.create') as mock_create, \
         patch('app.login_user') as mock_login:

        # Configure discovery endpoint response
        discovery_response = Mock()
        discovery_response.json = lambda: mock_provider_config
        discovery_response.ok = True

        # Configure userinfo endpoint response
        userinfo_response = Mock()
        userinfo_response.json = lambda: mock_user_info
        userinfo_response.ok = True

        # Configure token endpoint response
        token_response = Mock()
        token_response.json = lambda: {
            "access_token": "dummy_token",
            "id_token": "dummy_id_token",
            "token_type": "Bearer"
        }
        token_response.ok = True
        mock_post.return_value = token_response

        # Configure the GET mock based on URL
        def get_response(url):
            if 'openid-configuration' in url:
                return discovery_response
            return userinfo_response

        mock_get.side_effect = lambda url, **kwargs: get_response(url)

        response = sso_client.get('/login/google/callback?code=dummy_code')

        assert response.status_code == HTTPStatus.FOUND  # 302 redirect
        assert mock_create.called
        mock_create.assert_called_with(
            mock_user_info["sub"],
            "GOOGLE",
            mock_user_info["given_name"],
            mock_user_info["email"],
            mock_user_info["picture"]
        )
        assert mock_login.called

def test_google_callback_missing_code(sso_client):
    """Test callback handling when authorization code is missing."""
    response = sso_client.get('/login/google/callback')
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert b'Authorization code not received' in response.data

def test_google_callback_invalid_provider(sso_client):
    """Test callback with invalid provider."""
    response = sso_client.get('/login/invalid_provider/callback?code=dummy_code')
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert b'Unsupported authentication provider' in response.data

@patch('requests.get')
@patch('requests.post')
def test_google_callback_token_error(mock_post, mock_get, sso_client):
    """Test handling of token exchange error."""
    # Mock the OAuth provider configuration
    mock_provider_config = {
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
    }

    discovery_response = Mock()
    discovery_response.json = lambda: mock_provider_config
    discovery_response.ok = True

    token_response = Mock()
    token_response.ok = False
    token_response.status_code = HTTPStatus.UNAUTHORIZED

    # Configure the GET mock based on URL
    def get_response(url):
        """Return appropriate mock response based on URL.
        
        Args:
            url: The request URL
            
        Returns:
            Mock: Configured mock response
        """
        if 'openid-configuration' in url:
            return discovery_response
        return token_response

    mock_get.side_effect = lambda url, **kwargs: get_response(url)
    mock_post.return_value = token_response

    response = sso_client.get('/login/google/callback?code=dummy_code')
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert b'Failed to get user info' in response.data

@patch('requests.get')
@patch('requests.post')
def test_google_callback_userinfo_error(mock_post, mock_get, sso_client):
    """Test handling of userinfo endpoint error."""
    # Mock the OAuth provider configuration
    mock_provider_config = {
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v2/userinfo"
    }

    # Configure discovery endpoint response
    discovery_response = Mock()
    discovery_response.json = lambda: mock_provider_config
    discovery_response.ok = True

    # Configure userinfo endpoint response
    userinfo_response = Mock()
    userinfo_response.ok = False
    userinfo_response.status_code = 401

    # Configure token endpoint response
    token_response = Mock()
    token_response.json = lambda: {
        "access_token": "dummy_token",
        "id_token": "dummy_id_token",
        "token_type": "Bearer"
    }
    token_response.ok = True
    mock_post.return_value = token_response

    # Configure the GET mock based on URL
    def get_response(url):
        if 'openid-configuration' in url:
            return discovery_response
        return userinfo_response

    mock_get.side_effect = lambda url, **kwargs: get_response(url)

    response = sso_client.get('/login/google/callback?code=dummy_code')
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert b'Failed to get user info' in response.data

@patch('requests.get')
@patch('requests.post')
def test_google_callback_missing_email(mock_post, mock_get, sso_client):
    """Test handling of userinfo response missing required fields."""
    # Mock the OAuth provider configuration
    mock_provider_config = {
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v2/userinfo"
    }

    def get_side_effect(*args):
        mock_response = Mock()
        if 'openid-configuration' in args[0]:
            # Provider configuration request
            mock_response.json = lambda: mock_provider_config
            mock_response.ok = True
        elif 'userinfo' in args[0]:
            # Userinfo request - missing email
            mock_response.json = lambda: {
                "sub": "12345",
                "provider": "GOOGLE",
                "given_name": "Test User",
                "picture": "https://example.com/pic.jpg"
            }
            mock_response.ok = True
        mock_response.raise_for_status = Mock()
        return mock_response

    mock_get.side_effect = get_side_effect

    # Mock token exchange success
    mock_token_response = Mock()
    mock_token_response.json = lambda: {
        "access_token": "dummy_token",
        "id_token": "dummy_id_token",
        "token_type": "Bearer"
    }
    mock_token_response.ok = True
    mock_token_response.raise_for_status = Mock()
    mock_post.return_value = mock_token_response

    response = sso_client.get('/login/google/callback?code=dummy_code')
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR  # This is correct - we get 500 when user info is invalid
    assert b'Authentication failed' in response.data

def test_auth_provider_enum():
    """Test AuthProvider enum configuration."""
    assert AuthProvider.GOOGLE.discovery_url == \
        "https://accounts.google.com/.well-known/openid-configuration"
    assert "openid" in AuthProvider.GOOGLE.required_scopes()
    assert AuthProvider.GOOGLE.client_id_env_var == "GOOGLE_CLIENT_ID"

def test_logout_without_login(sso_client):
    """Test logout when not logged in."""
    response = sso_client.get('/logout')
    assert response.status_code == HTTPStatus.UNAUTHORIZED

@patch('requests.get')
@patch('requests.post')
def test_existing_user_login(mock_post, mock_get, sso_client):
    """Test successful login for existing user."""
    # Mock user info response
    mock_user_info = {
        "sub": "12345",
        "given_name": "Test User",
        "email": "test@example.com",
        "picture": "https://example.com/pic.jpg"
    }

    # Mock existing user
    mock_existing_user = Mock()
    mock_existing_user.id = mock_user_info["sub"]
    mock_existing_user.name = mock_user_info["given_name"]
    mock_existing_user.email = mock_user_info["email"]
    mock_existing_user.profile_pic = mock_user_info["picture"]
    mock_existing_user.provider = "GOOGLE"

    with patch('app.User.get', return_value=mock_existing_user), \
         patch('app.User.create') as mock_create, \
         patch('app.login_user') as mock_login:

        # Configure responses (similar to test_google_callback_success)
        discovery_response = Mock()
        discovery_response.json = lambda: {
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v2/userinfo"
        }
        discovery_response.ok = True

        userinfo_response = Mock()
        userinfo_response.json = lambda: mock_user_info
        userinfo_response.ok = True

        token_response = Mock()
        token_response.json = lambda: {
            "access_token": "dummy_token",
            "id_token": "dummy_id_token",
            "token_type": "Bearer"
        }
        token_response.ok = True
        mock_post.return_value = token_response

        mock_get.side_effect = lambda url, **kwargs: \
            discovery_response if 'openid-configuration' in url else userinfo_response

        response = sso_client.get('/login/google/callback?code=dummy_code')

        assert response.status_code == HTTPStatus.FOUND
        assert not mock_create.called  # Should not create new user
        assert mock_login.called
        mock_login.assert_called_with(ANY)

        # Verify the user attributes instead
        actual_user = mock_login.call_args[0][0]
        assert actual_user.id == mock_existing_user.id
        assert actual_user.name == mock_existing_user.name
        assert actual_user.email == mock_existing_user.email
        assert actual_user.profile_pic == mock_existing_user.profile_pic
        assert actual_user.provider == mock_existing_user.provider

@patch('requests.get')
@patch('requests.post')
def test_multiple_logins_same_user(mock_post, mock_get, sso_client):
    """Test user can log in multiple times."""
    # Mock user info response
    mock_user_info = {
        "sub": "12345",
        "given_name": "Test User",
        "email": "test@example.com",
        "picture": "https://example.com/pic.jpg"
    }

    # Mock existing user
    mock_existing_user = Mock()
    mock_existing_user.id = mock_user_info["sub"]
    mock_existing_user.name = mock_user_info["given_name"]
    mock_existing_user.email = mock_user_info["email"]
    mock_existing_user.profile_pic = mock_user_info["picture"]
    mock_existing_user.provider = "GOOGLE"

    with patch('app.User.get', return_value=mock_existing_user), \
         patch('app.User.create'):

        # Configure responses
        discovery_response = Mock()
        discovery_response.json = lambda: {
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v2/userinfo"
        }
        discovery_response.ok = True

        userinfo_response = Mock()
        userinfo_response.json = lambda: mock_user_info
        userinfo_response.ok = True

        token_response = Mock()
        token_response.json = lambda: {
            "access_token": "dummy_token",
            "id_token": "dummy_id_token",
            "token_type": "Bearer"
        }
        token_response.ok = True
        mock_post.return_value = token_response

        mock_get.side_effect = lambda url, **kwargs: \
            discovery_response if 'openid-configuration' in url else userinfo_response

        # First login
        response1 = sso_client.get('/login/google/callback?code=dummy_code1')
        assert response1.status_code == HTTPStatus.FOUND

        with patch('app.logout_user'):
            sso_client.get('/logout')

        # Second login
        response2 = sso_client.get('/login/google/callback?code=dummy_code2')
        assert response2.status_code == HTTPStatus.FOUND

@patch('app.logout_user')
def test_successful_logout(mock_logout, sso_client):
    """Test successful logout for logged-in user."""
    with sso_client.session_transaction() as sess:
        sess['_user_id'] = "12345"  # Set Flask-Login session

    response = sso_client.get('/logout')

    assert response.status_code == HTTPStatus.FOUND
    assert mock_logout.called
