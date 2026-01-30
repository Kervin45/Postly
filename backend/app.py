from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from config import Config
from database.db import db
from auth.routes import auth_bp
from posts.routes import posts_bp
from models.user import User  # 🔥 ADD THIS IMPORT

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, supports_credentials=True)

    db.init_app(app)
    JWTManager(app)

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(posts_bp, url_prefix="/posts")

    with app.app_context():
        db.create_all()
        print("Database and tables created!")

    # 🔥 ADD DEBUG ROUTE HERE (proper indentation)
    @app.route("/debug/users")
    def debug_users():
        users_count = User.query.count()
        users = User.query.all()
        return {
            "count": users_count,
            "users": [
                {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email
                }
                for user in users
            ]
        }

    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
