from flask import Flask
from core.config import Config
from utils.logging import setup_logging
from auth.routes import auth_bp

def create_app(config: Optional[Config] = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load configuration
    if config is None:
        config = Config.from_env()
    
    app.config.from_object(config)
    
    # Setup logging
    setup_logging(config.LOG_LEVEL)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    return app

# Only used when running directly
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)


