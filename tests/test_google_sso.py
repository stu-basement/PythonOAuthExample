import os
import pytest
from unittest.mock import patch, Mock
from flask import url_for
from http import HTTPStatus
from app import create_app, AuthProvider

@pytest.fixture
def app():
    """Create application for the tests."""
    # Allow OAuth without HTTPS in testing
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    
    app = create_app({
        'TESTING': True,
        'SECRET_KEY': 'test_secret_key',
        'GOOGLE_CLIENT_ID': 'test_client_id',
        'GOOGLE_CLIENT_SECRET': 'test_client_secret'
    })
    return app

@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()

@pytest.fixture
def mock_google_config():
    return {
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v2/userinfo"
    }

def test_google_login_button_present(client):
    """Test that Google login button appears on index page."""
    response = client.get('/')
    assert response.status_code == HTTPStatus.OK
    assert b'href="/login/google"' in response.data

def test_google_login_redirect(client, mock_google_config, app):
    """Test that /login/google redirects to Google's auth endpoint."""
    with patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = mock_google_config
        mock_get.return_value.ok = True
        
        response = client.get('/login/google')
        assert response.status_code == HTTPStatus.FOUND  # 302 redirect
        assert 'accounts.google.com' in response.headers['Location']
        assert 'openid' in response.headers['Location']
        assert 'email' in response.headers['Location']
        assert 'profile' in response.headers['Location']

def test_google_login_missing_client_id(client, app):
    """Test handling of missing Google client ID."""
    app.config['GOOGLE_CLIENT_ID'] = None
    response = client.get('/login/google')
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert b'Client ID not configured' in response.data

def test_google_callback_success(client):
    """Test successful Google callback handling."""
    mock_user_info = {
        "sub": "12345",
        "given_name": "Test User",
        "email": "test@example.com",
        "picture": "https://example.com/pic.jpg"
    }

    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post, \
         patch('app.User.get', return_value=None), \
         patch('app.User.create') as mock_create, \
         patch('app.login_user') as mock_login:
        
        # Mock the OAuth provider configuration
        mock_provider_config = {
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v2/userinfo"
        }

        # Set up the mock responses for different requests
        def get_side_effect(*args, **kwargs):
            mock_response = Mock()
            
            # Provider configuration endpoint
            if '.well-known/openid-configuration' in args[0]:
                mock_response.json.return_value = mock_provider_config
                mock_response.ok = True
            # User info endpoint
            elif 'userinfo' in args[0]:
                mock_response.json.return_value = mock_user_info
                mock_response.ok = True
            
            mock_response.raise_for_status = Mock()
            return mock_response
        
        mock_get.side_effect = get_side_effect

        # Mock the token exchange response
        mock_token_response = Mock()
        mock_token_response.json.return_value = {
            "access_token": "dummy_token",
            "id_token": "dummy_id_token",
            "token_type": "Bearer"
        }
        mock_token_response.ok = True
        mock_post.return_value = mock_token_response
        
        response = client.get('/login/google/callback?code=dummy_code')
        
        # Debug output
        print(f"Response status: {response.status_code}")
        print(f"Response data: {response.data}")
        
        assert response.status_code == HTTPStatus.FOUND  # 302 redirect
        assert mock_create.called
        mock_create.assert_called_with(
            mock_user_info["sub"],
            mock_user_info["given_name"],
            mock_user_info["email"],
            mock_user_info["picture"]
        )
        assert mock_login.called

def test_google_callback_missing_code(client):
    """Test callback handling when authorization code is missing."""
    response = client.get('/login/google/callback')
    assert response.status_code == HTTPStatus.BAD_REQUEST  # 400
    assert b'Authorization code not received' in response.data

def test_google_callback_invalid_user_info(client):
    """Test callback handling when user info is invalid."""
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post:
        
        # Mock the OAuth provider configuration
        mock_provider_config = {
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v2/userinfo"
        }

        # Set up the mock responses
        def get_side_effect(*args, **kwargs):
            mock_response = Mock()
            if '.well-known/openid-configuration' in args[0]:
                # Provider configuration request succeeds
                mock_response.json.return_value = mock_provider_config
                mock_response.ok = True
            elif 'userinfo' in args[0]:
                # User info request fails
                mock_response.ok = False
                mock_response.status_code = 401
            mock_response.raise_for_status = Mock()
            return mock_response
        
        mock_get.side_effect = get_side_effect

        # Mock the token response
        mock_token_response = Mock()
        mock_token_response.json.return_value = {
            "access_token": "dummy_token",
            "id_token": "dummy_id_token",
            "token_type": "Bearer"
        }
        mock_token_response.ok = True
        mock_token_response.raise_for_status = Mock()
        mock_post.return_value = mock_token_response
        
        response = client.get('/login/google/callback?code=dummy_code')
        
        assert response.status_code == HTTPStatus.UNAUTHORIZED  # 401
        assert b'Failed to get user info' in response.data

def test_auth_provider_enum():
    """Test AuthProvider enum configuration."""
    assert AuthProvider.GOOGLE.discovery_url == \
        "https://accounts.google.com/.well-known/openid-configuration"
    assert "openid" in AuthProvider.GOOGLE.required_scopes()
    assert AuthProvider.GOOGLE.client_id_env_var == "GOOGLE_CLIENT_ID" 