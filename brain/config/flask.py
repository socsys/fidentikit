def config_flask(app):
    app.url_map.strict_slashes = False
    app.jinja_env.policies["json.dumps_kwargs"] = {"sort_keys": False}
    
    # Handle subpath deployment
    application_root = app.config.get('APPLICATION_ROOT', '')
    if application_root:
        app.config['APPLICATION_ROOT'] = application_root
    
    # Include APPLICATION_ROOT in server URLs for OpenAPI
    base_url = f"//{app.config['BRAIN_EXTERNAL_DOMAIN']}{application_root}"
    app.servers = [
        {"name": "Production", "url": base_url},
        {"name": "Development", "url": f"//localhost:8080{application_root}"}
    ]
    
    # Make APPLICATION_ROOT available in all templates
    @app.context_processor
    def inject_application_root():
        return {'application_root': app.config.get('APPLICATION_ROOT', '')}
