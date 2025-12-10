from apiflask import APIFlask
from config.env import config_env
from config.logging import config_logging
from config.flask import config_flask
from config.mongodb import config_mongodb
from config.rabbitmq import config_rabbitmq
from config.minio import config_minio
from config.celery import config_celery
from config.cache import config_cache
from blueprints.bp_views import bp_views
from blueprints.bp_api import bp_api


def create_app():
    app = APIFlask(__name__, title="FidentiKit")

    config_env(app)
    config_logging(app)
    config_flask(app)
    config_mongodb(app)
    config_rabbitmq(app)
    config_minio(app)
    config_celery(app)
    config_cache(app)

    # Handle subpath deployment (e.g., /softwares/fidentikit)
    # Use ProxyFix to handle X-Forwarded-* headers
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_prefix=1)
    
    # WSGI middleware to handle X-Script-Name header for subpath deployment
    class ScriptNameMiddleware:
        def __init__(self, app):
            self.app = app
        
        def __call__(self, environ, start_response):
            script_name = environ.get('HTTP_X_SCRIPT_NAME', '')
            if script_name:
                environ['SCRIPT_NAME'] = script_name
                app.config['APPLICATION_ROOT'] = script_name
            return self.app(environ, start_response)
    
    app.wsgi_app = ScriptNameMiddleware(app.wsgi_app)

    app.register_blueprint(bp_views)
    app.register_blueprint(bp_api)

    # Configure app with initialization
    with app.app_context():
        # Initialize database indexes
        try:
            from blueprints.api.bp_init import initialize_database
            if initialize_database(app.config["db"]):
                app.logger.info("Database initialization completed successfully")
            else:
                app.logger.warning("Database initialization completed with warnings")
        except Exception as e:
            app.logger.error(f"Error during app initialization: {e}")
            # Continue anyway as this shouldn't stop the app from functioning

    return app

# Standard WSGI handler for production deployments
application = create_app()

if __name__ == "__main__":
    application.run()
