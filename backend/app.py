#!/usr/bin/env python3
from flask import Flask, render_template
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from config import Config
from database.db import db
from auth.routes import auth_bp
from posts.routes import posts_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Enable CORS for all routes
    CORS(app, resources={r"/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}})
    
    # Initialize extensions
    db.init_app(app)
    JWTManager(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(posts_bp, url_prefix="/posts")
    
    # Create database tables
    with app.app_context():
        db.create_all()
        print("Database and tables created!")
    
    return app

app = create_app()

# # UI routes
# @app.route("/")
# def index():
#     return render_template("index.html")

# @app.route("/login-ui")
# def login_ui():
#     return render_template("login.html")

# @app.route("/register-ui")
# def register_ui():
#     return render_template("register.html")

# @app.route("/posts-ui")
# def posts_ui():
#     return render_template("posts.html")

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
