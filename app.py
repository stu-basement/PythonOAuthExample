# Python standard libraries
import json
import os
import logging

from http import HTTPStatus
from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional
# Third-party libraries
from flask import Flask, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

# Internal imports
from user import User
from db import init_database

# Configuration constants
SECRET_KEY_BYTES = 24  # Number of random bytes for secure secret key
DEFAULT_REQUEST_TIMEOUT = 5  # seconds
PROVIDER_CONFIG_CACHE_SECONDS = 86400  # 24 hours in seconds
DEFAULT_CONNECT_TIMEOUT = 3  # seconds
DEFAULT_READ_TIMEOUT = 5  # seconds

class AuthProvider(Enum):
    GOOGLE = auto()
    META = auto()
    APPLE = auto()
    EMAIL = auto()

    @property
    def provider_name(self) -> str:
        """Get the provider name in lowercase.
        
        Returns:
            str: Provider name in lowercase (e.g., 'google', 'facebook')
        """
        return self.name.upper()

    @property
    def discovery_url(self) -> Optional[str]:
        urls = {
            AuthProvider.GOOGLE:
            "https://accounts.google.com/.well-known/openid-configuration",
            AuthProvider.META:
            "https://www.facebook.com/.well-known/openid-configuration",
            AuthProvider.APPLE:
            "https://appleid.apple.com/.well-known/openid-configuration",
            AuthProvider.EMAIL: None
        }
        return urls[self]

    @property
    def token_endpoint(self) -> Optional[str]:
        ''' Get the token endpoint for the provider '''
        endpoints = {
            AuthProvider.GOOGLE: None, # Uses discovery
            AuthProvider.META: "https://graph.facebook.com/v18.0/oauth/access_token",
            AuthProvider.APPLE: None, # TBD
            AuthProvider.EMAIL: None # TBD
        }
        return endpoints[self]

    @property
    def userinfo_endpoint(self) -> Optional[str]:
        """Get the userinfo endpoint for the provider."""
        endpoints = {
            AuthProvider.GOOGLE: None,  # Uses discovery
            AuthProvider.META: "https://graph.facebook.com/v18.0/me?fields=id,name,email,picture",
            AuthProvider.APPLE: None,  # Uses discovery
            AuthProvider.EMAIL: None
        }
        return endpoints[self]

    @property
    def client_id_env_var(self) -> str:
        """Environment variable name for client ID."""
        return f"{self.name}_CLIENT_ID"

    @property
    def client_secret_env_var(self) -> str:
        """Environment variable name for client secret."""
        return f"{self.name}_CLIENT_SECRET"

    def required_scopes(self) -> list[str]:
        """Get the required OAuth scopes for the provider."""
        scopes = {
            AuthProvider.GOOGLE: ["openid", "email", "profile"],
            AuthProvider.META: ["email", "public_profile"],
            AuthProvider.APPLE: ["name", "email"],
            AuthProvider.EMAIL: []
        }
        return scopes[self]

@dataclass
class OAuthConfig:
    client_id: str
    client_secret: str
    provider: AuthProvider

def create_app(config=None):
    """Application factory function."""

    # Create Flask app instance
    app = Flask(__name__)

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    app.logger = logging.getLogger('auth')

    # Set secret key first - this is required for sessions
    app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

    # Set remaining configuration
    app.config.from_mapping(
        GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID", None),
        GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET", None),
        META_CLIENT_ID=os.environ.get("META_CLIENT_ID", None),
        META_CLIENT_SECRET=os.environ.get("META_CLIENT_SECRET", None),
    )

    # Override with test config if provided
    if config:
        # Ensure secret_key isn't overridden unless explicitly provided
        if 'SECRET_KEY' in config:
            app.secret_key = config['SECRET_KEY']
        app.config.from_mapping(config)

    # Initialize database
    init_database(app)

    # Initialize extensions
    login_manager = LoginManager()
    login_manager.init_app(app)

    # Register user loader
    @login_manager.user_loader
    def load_user(user_id):
        return User.get(user_id)

    # Register routes
    register_routes(app)

    return app

def register_index_route(app):
    @app.route("/")
    def index():
        try:
            if current_user.is_authenticated:
                return (
                    f"<p>Hello, {current_user.name}! You're logged in!"
                    f"Email: {current_user.email}</p>"
                    f"<div><p>Profile Picture:</p>"
                    f'<img src="{current_user.profile_pic}" alt="profile pic"></img></div>'
                    f'<a class="button" href="/logout">Logout</a>'
                ), HTTPStatus.OK
            return (
                '<a class="button" href="/login/google">Google Login</a><br>'
                '<a class="button" href="/login/meta">Meta Login</a><br>'
                '<a class="button" href="/login/apple">Apple Login</a><br>'
                '<a class="button" href="/login/email">Email Login</a>'
            ), HTTPStatus.OK
        except Exception as e:
            print(f"Index page error: {e}")
            return "Failed to load page.", HTTPStatus.INTERNAL_SERVER_ERROR

def register_login_route(app):
    @app.route("/login/<provider>")
    def login(provider: str):
        try:
            auth_provider = AuthProvider[provider.upper()]
        except KeyError:
            app.logger.warning(f"Login attempt with invalid provider: {provider}")
            return f"Unsupported authentication provider: {provider}", HTTPStatus.BAD_REQUEST

        if auth_provider == AuthProvider.EMAIL:
            app.logger.info("Redirecting to email login")
            return redirect(url_for("email_login"))

        client_id = app.config.get(f"{auth_provider.name}_CLIENT_ID")
        if not client_id:
            app.logger.error(f"Missing client ID for {auth_provider.name}")
            return f"{auth_provider.name} Client ID not configured.", HTTPStatus.INTERNAL_SERVER_ERROR

        provider_cfg = get_provider_cfg(auth_provider)
        if not provider_cfg:
            app.logger.error(f"Failed to get provider configuration for {auth_provider.name}")
            return f"Failed to get {auth_provider.name} configuration.", HTTPStatus.SERVICE_UNAVAILABLE

        try:
            authorization_endpoint = provider_cfg["authorization_endpoint"]
            client = WebApplicationClient(client_id)
            request_uri = client.prepare_request_uri(
                authorization_endpoint,
                redirect_uri=request.base_url + "/callback",
                scope=auth_provider.required_scopes(),
            )
            app.logger.info(f"Initiating {auth_provider.name} login flow for user")
            return redirect(request_uri)
        except Exception as e:
            app.logger.error(f"Login preparation failed for {auth_provider.name}: {str(e)}",
                             exc_info=True)
            return "Failed to prepare login request.", HTTPStatus.INTERNAL_SERVER_ERROR

def map_oauth_user_info(provider: AuthProvider, user_info: dict) -> dict:
    """Map provider-specific user info to standard format.
    
    Args:
        provider: The authentication provider
        user_info: Provider-specific user info
        
    Returns:
        dict: Standardized user info with keys:
            - id: Unique user identifier
            - name: User's display name
            - email: User's email
            - picture: URL to profile picture
    """
    if provider == AuthProvider.GOOGLE:
        return {
            "id": user_info["sub"],
            "name": user_info.get("given_name", user_info.get("name")),
            "email": user_info["email"],
            "picture": user_info.get("picture")
        }

    if provider == AuthProvider.META:
        return {
            "id": user_info["id"],
            "name": user_info.get("name"),
            "email": user_info["email"],
            "picture": user_info.get("picture", {}).get("data", {}).get("url")
        }
    return {}

def register_login_callback_route(app):
    @app.route("/login/<provider>/callback")
    def callback(provider: str):
        try:
            auth_provider = AuthProvider[provider.upper()]
        except KeyError:
            app.logger.warning(f"Callback received for invalid provider: {provider}")
            return f"Unsupported authentication provider: {provider}", HTTPStatus.BAD_REQUEST

        code = request.args.get("code")
        if not code:
            app.logger.warning(f"No authorization code received in callback for {auth_provider.provider_name}")
            return "Authorization code not received.", HTTPStatus.BAD_REQUEST

        try:
            oauth_config = OAuthConfig(
                client_id=os.environ.get(auth_provider.client_id_env_var),
                client_secret=os.environ.get(auth_provider.client_secret_env_var),
                provider=auth_provider
            )

            user_info = get_oauth_user_info(code, oauth_config)
            if not user_info:
                app.logger.error(f"Failed to get user info from {auth_provider.name}")
                return "Failed to get user info.", HTTPStatus.UNAUTHORIZED

            # Create/update user in database
            mapped_info = map_oauth_user_info(auth_provider, user_info)
            user = User(
                id_=mapped_info["id"],
                provider=auth_provider.provider_name,
                name=mapped_info.get("name"),
                email=mapped_info["email"],
                profile_pic=mapped_info.get("picture")
            )

            if not User.get(user.id):
                app.logger.info(f"Creating new user account for {user.email} from {auth_provider.provider_name}")
                User.create(user.id, user.provider, user.name, user.email, user.profile_pic)
            else:
                app.logger.info(f"Existing user logged in: {user.email}")

            login_user(user)
            app.logger.info(f"Successfully logged in user: {user.email}")
            return redirect(url_for("index"))

        except Exception as e:
            app.logger.error(f"Authentication failed for {auth_provider.name}: {str(e)}", exc_info=True)
            return "Authentication failed.", HTTPStatus.INTERNAL_SERVER_ERROR

def register_logout_route(app):
    @app.route("/logout")
    @login_required
    def logout():
        try:
            email = current_user.email  # Store email before logout
            logout_user()
            app.logger.info(f"User logged out: {email}")
            return redirect(url_for("index"))
        except Exception as e:
            app.logger.error(f"Logout failed: {str(e)}", exc_info=True)
            return "Logout failed.", HTTPStatus.INTERNAL_SERVER_ERROR

def register_routes(app):
    """Register all routes with the app."""
    # All your existing routes go here

    register_index_route(app)
    register_login_route(app)
    register_login_callback_route(app)
    register_logout_route(app)

def get_oauth_user_info(code: str, config: OAuthConfig) -> Optional[dict]:
    """Get user info from OAuth provider."""
    provider_cfg = get_provider_cfg(config.provider)
    if not provider_cfg:
        return None

    client = WebApplicationClient(config.client_id)

    # Get tokens
    token_endpoint = provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )

    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(config.client_id, config.client_secret),
        timeout=(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT),
    )

    if not token_response.ok:
        return None

    client.parse_request_body_response(json.dumps(token_response.json()))

    # Get user info
    userinfo_endpoint = provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(
        uri,
        headers=headers,
        data=body,
        timeout=(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT),
        )

    if not userinfo_response.ok:
        return None

    return userinfo_response.json()

def get_provider_cfg(provider: AuthProvider) -> Optional[dict]:
    """Fetch provider configuration with caching."""
    if provider == AuthProvider.EMAIL:
        return None # TBD

    if provider == AuthProvider.META:
        return {
            "authorization_endpoint": "https://www.facebook.com/v18.0/dialog/oauth",
            "token_endpoint": provider.token_endpoint,
            "userinfo_endpoint": provider.userinfo_endpoint
        }

    try:
        response = requests.get(
            provider.discovery_url,
            timeout=(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)
        )
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as e:
        print(f"Failed to fetch {provider.name} configuration: {e}")
        return None

# Create the application
ssoapp = create_app()

if __name__ == "__main__":
    ssoapp.run(ssl_context="adhoc")
