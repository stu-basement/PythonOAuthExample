# Python standard libraries
import json
import os
import sqlite3

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
from http import HTTPStatus
from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional

# Internal imports
from db import init_db_command
from user import User

# Configuration constants
SECRET_KEY_BYTES = 24  # Number of random bytes for secure secret key
DEFAULT_REQUEST_TIMEOUT = 5  # seconds
PROVIDER_CONFIG_CACHE_SECONDS = 86400  # 24 hours in seconds
DEFAULT_CONNECT_TIMEOUT = 3  # seconds
DEFAULT_READ_TIMEOUT = 5  # seconds

# Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional

class AuthProvider(Enum):
    GOOGLE = auto()
    FACEBOOK = auto()
    APPLE = auto()
    EMAIL = auto()

    @property
    def discovery_url(self) -> Optional[str]:
        urls = {
            AuthProvider.GOOGLE: "https://accounts.google.com/.well-known/openid-configuration",
            AuthProvider.FACEBOOK: "https://www.facebook.com/.well-known/openid-configuration",
            AuthProvider.APPLE: "https://appleid.apple.com/.well-known/openid-configuration",
            AuthProvider.EMAIL: None
        }
        return urls[self]
    
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
            AuthProvider.FACEBOOK: ["email", "public_profile"],
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
    
    # Set secret key first - this is required for sessions
    app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)
    
    # Set remaining configuration
    app.config.from_mapping(
        GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID", None),
        GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET", None),
    )
    
    # Override with test config if provided
    if config:
        # Ensure secret_key isn't overridden unless explicitly provided
        if 'SECRET_KEY' in config:
            app.secret_key = config['SECRET_KEY']
        app.config.from_mapping(config)
    
    # Initialize extensions
    login_manager = LoginManager()
    login_manager.init_app(app)
    
    # Initialize database
    try:
        init_db_command()
    except Exception as e:
        print(f"Database initialization failed: {e}")
    
    # Register user loader
    @login_manager.user_loader
    def load_user(user_id):
        return User.get(user_id)
    
    # Register routes
    register_routes(app)
    
    return app

def register_routes(app):
    """Register all routes with the app."""
    # All your existing routes go here
    @app.route("/")
    def index():
        try:
            if current_user.is_authenticated:
                return (
                    "<p>Hello, {}! You're logged in! Email: {}</p>"
                    "<div><p>Profile Picture:</p>"
                    '<img src="{}" alt="profile pic"></img></div>'
                    '<a class="button" href="/logout">Logout</a>'.format(
                        current_user.name, current_user.email, current_user.profile_pic
                    )
                )
            else:
                return (
                    '<a class="button" href="/login/google">Google Login</a><br>'
                    '<a class="button" href="/login/facebook">Facebook Login</a><br>'
                    '<a class="button" href="/login/apple">Apple Login</a><br>'
                    '<a class="button" href="/login/email">Email Login</a>'
                ), HTTPStatus.OK
        except Exception as e:
            print(f"Index page error: {e}")
            return "Failed to load page.", HTTPStatus.INTERNAL_SERVER_ERROR

    @app.route("/login/<provider>")
    def login(provider: str):
        try:
            auth_provider = AuthProvider[provider.upper()]
        except KeyError:
            return f"Unsupported authentication provider: {provider}", HTTPStatus.BAD_REQUEST

        # Handle email/password login separately
        if auth_provider == AuthProvider.EMAIL:
            return redirect(url_for("email_login"))

        # Get client credentials
        client_id = os.environ.get(auth_provider.client_id_env_var)
        if not client_id:
            return f"{auth_provider.name} Client ID not configured.", HTTPStatus.INTERNAL_SERVER_ERROR

        # Get provider configuration
        provider_cfg = get_provider_cfg(auth_provider)
        if not provider_cfg:
            return (f"Failed to get {auth_provider.name} provider configuration.", 
                    HTTPStatus.SERVICE_UNAVAILABLE)

        try:
            authorization_endpoint = provider_cfg["authorization_endpoint"]
            client = WebApplicationClient(client_id)
            request_uri = client.prepare_request_uri(
                authorization_endpoint,
                redirect_uri=request.base_url + "/callback",
                scope=auth_provider.required_scopes(),
            )
            return redirect(request_uri)
        except Exception as e:
            print(f"Login preparation failed: {e}")
            return "Failed to prepare login request.", HTTPStatus.INTERNAL_SERVER_ERROR

    @app.route("/login/<provider>/callback")
    def callback(provider: str):
        try:
            auth_provider = AuthProvider[provider.upper()]
        except KeyError:
            return f"Unsupported authentication provider: {provider}", HTTPStatus.BAD_REQUEST

        code = request.args.get("code")
        if not code:
            return "Authorization code not received.", HTTPStatus.BAD_REQUEST

        try:
            oauth_config = OAuthConfig(
                client_id=os.environ.get(auth_provider.client_id_env_var),
                client_secret=os.environ.get(auth_provider.client_secret_env_var),
                provider=auth_provider
            )
            
            user_info = get_oauth_user_info(code, oauth_config)
            if not user_info:
                return "Failed to get user info.", HTTPStatus.UNAUTHORIZED

            # Create/update user in database
            user = User(
                id_=user_info["sub"],
                name=user_info["given_name"],
                email=user_info["email"],
                profile_pic=user_info.get("picture")
            )

            if not User.get(user.id):
                User.create(user.id, user.name, user.email, user.profile_pic)

            login_user(user)
            return redirect(url_for("index"))

        except Exception as e:
            print(f"Callback failed: {e}")
            return "Authentication failed.", HTTPStatus.INTERNAL_SERVER_ERROR

    @app.route("/logout")
    @login_required
    def logout():
        try:
            logout_user()
            return redirect(url_for("index"))
        except Exception as e:
            print(f"Logout failed: {e}")
            return "Logout failed.", HTTPStatus.INTERNAL_SERVER_ERROR

    # Configuration validation at startup
    def validate_config():
        missing_configs = []
        
        if not GOOGLE_CLIENT_ID:
            missing_configs.append("GOOGLE_CLIENT_ID")
        if not GOOGLE_CLIENT_SECRET:
            missing_configs.append("GOOGLE_CLIENT_SECRET")
        
        if missing_configs:
            raise RuntimeError(
                f"Missing required environment variables: {', '.join(missing_configs)}\n"
                "Please set these variables before starting the application."
            )

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
        )

        if not token_response.ok:
            return None

        client.parse_request_body_response(json.dumps(token_response.json()))

        # Get user info
        userinfo_endpoint = provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body)

        if not userinfo_response.ok:
            return None

        return userinfo_response.json()

    def get_provider_cfg(provider: AuthProvider) -> Optional[dict]:
        """Fetch provider configuration with caching."""
        if provider == AuthProvider.EMAIL:
            return None
        
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
app = create_app()

if __name__ == "__main__":
    app.run(ssl_context="adhoc")


