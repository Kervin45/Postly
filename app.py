from flask import Flask, render_template
from flask_jwt_extended import JWTManager

from config import Config
from database.db import db
from auth.routes import auth_bp
from posts.routes import posts_bp
from models.user import User
from models.post import Post


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    JWTManager(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(posts_bp)

    # Create tables
    with app.app_context():
        db.create_all()
        print("Database and tables created!")

    return app


app = create_app()

# UI routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login-ui")
def login_ui():
    return render_template("login.html")

@app.route("/register-ui")
def register_ui():
    return render_template("register.html")

@app.route("/posts-ui")
def posts_ui():
    return render_template("posts.html")


if __name__ == "__main__":
    app.run(debug=True)


