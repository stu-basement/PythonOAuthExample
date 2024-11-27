import pytest
from unittest.mock import patch, Mock
from flask import url_for
from http import HTTPStatus
from app import app, AuthProvider

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

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

@patch('app.get_provider_cfg')
def test_google_login_redirect(mock_get_cfg, client, mock_google_config):
    """Test that /login/google redirects to Google's auth endpoint."""
    mock_get_cfg.return_value = mock_google_config
    
    with patch.dict('os.environ', {'GOOGLE_CLIENT_ID': 'dummy_id'}):
        response = client.get('/login/google')
        assert response.status_code == HTTPStatus.FOUND  # 302 redirect
        assert 'accounts.google.com' in response.headers['Location']
        assert 'openid' in response.headers['Location']
        assert 'email' in response.headers['Location']
        assert 'profile' in response.headers['Location']

def test_google_login_missing_client_id(client):
    """Test handling of missing Google client ID."""
    with patch.dict('os.environ', {'GOOGLE_CLIENT_ID': ''}):
        response = client.get('/login/google')
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        assert b'Client ID not configured' in response.data

@patch('app.get_oauth_user_info')
def test_google_callback_success(mock_get_user_info, client):
    """Test successful Google callback handling."""
    mock_user_info = {
        "sub": "12345",
        "given_name": "Test User",
        "email": "test@example.com",
        "picture": "https://example.com/pic.jpg"
    }
    mock_get_user_info.return_value = mock_user_info

    with patch('app.User.get', return_value=None), \
         patch('app.User.create') as mock_create, \
         patch('app.login_user') as mock_login:
        
        response = client.get('/login/google/callback?code=dummy_code')
        
        assert response.status_code == HTTPStatus.FOUND  # 302 redirect
        assert mock_create.called
        assert mock_login.called

def test_google_callback_missing_code(client):
    """Test callback handling when authorization code is missing."""
    response = client.get('/login/google/callback')
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert b'Authorization code not received' in response.data

@patch('app.get_oauth_user_info')
def test_google_callback_invalid_user_info(mock_get_user_info, client):
    """Test callback handling when user info is invalid."""
    mock_get_user_info.return_value = None
    
    response = client.get('/login/google/callback?code=dummy_code')
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert b'Failed to get user info' in response.data

def test_auth_provider_enum():
    """Test AuthProvider enum configuration."""
    assert AuthProvider.GOOGLE.discovery_url == \
        "https://accounts.google.com/.well-known/openid-configuration"
    assert "openid" in AuthProvider.GOOGLE.required_scopes()
    assert AuthProvider.GOOGLE.client_id_env_var == "GOOGLE_CLIENT_ID" 