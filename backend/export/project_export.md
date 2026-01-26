# Postly — Project Export

## Summary

Postly is a backend-first authentication foundation that implements secure user registration, password hashing, JWT issuance, and protected routes for token-based access control.

## Files

---

### app.py

```python
# Main application file
from flask import Flask
from flask_jwt_extended import JWTManager
from config import Config
from database.db import db
from auth.routes import auth_bp
from posts.routes import posts_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    JWTManager(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(posts_bp)

    with app.app_context():
        db.create_all()

    return app

app = create_app()

from flask_jwt_extended import jwt_required, get_jwt_identity

@app.route("/protected")
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    return {"message": f"Hello user {user_id}"}

if __name__ == "__main__":
    app.run(debug=True)
```

---

### config.py

```python
# Configuration settings
import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "postly-secret")
    SQLALCHEMY_DATABASE_URI = "sqlite:///postly.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-postly-secret")
```

---

### requirements.txt

```text
# Project dependencies
flask
flask-jwt-extended
flask-sqlalchemy
werkzeug
python-dotenv
```

---

### database/db.py

```python
# Database configuration and initialization
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
```

---

### auth/routes.py

```python
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from database.db import db
from models.user import User
from auth.utils import hash_password, verify_password

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No input data"}), 400

    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "User already exists"}), 409

    user = User(
        username=data["username"],
        email=data["email"],
        password_hash=hash_password(data["password"])
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    user = User.query.filter_by(email=data["email"]).first()

    if not user or not verify_password(data["password"], user.password_hash):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=user.id)

    return jsonify({"access_token": token}), 200
```

---

### auth/utils.py

```python
# Authentication utilities
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password):
    return generate_password_hash(password)

def verify_password(password, password_hash):
    return check_password_hash(password_hash, password)
```

---

### posts/routes.py

```python
from flask import Blueprint, request, jsonify, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from database.db import db
from models.post import Post
from models.user import User

posts_bp = Blueprint('posts', __name__, url_prefix='/posts')


@posts_bp.route('', methods=['POST'])
@jwt_required()
def create_post():
    data = request.get_json() or {}
    title = data.get('title')
    content = data.get('content')

    if not title or not content:
        return jsonify({"error": "title and content required"}), 400

    user_id = get_jwt_identity()
    post = Post(user_id=user_id, title=title, content=content)

    db.session.add(post)
    db.session.commit()

    return jsonify(post.to_dict()), 201


@posts_bp.route('', methods=['GET'])
def list_posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return jsonify([p.to_dict() for p in posts]), 200


@posts_bp.route('/<int:post_id>', methods=['GET'])
def get_post(post_id):
    post = Post.query.get_or_404(post_id)
    return jsonify(post.to_dict()), 200


def _authorize_post_action(post):
    user_id = get_jwt_identity()
    if post.user_id != user_id:
        abort(403)


@posts_bp.route('/<int:post_id>', methods=['PUT'])
@jwt_required()
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    _authorize_post_action(post)

    data = request.get_json() or {}
    title = data.get('title')
    content = data.get('content')

    if title:
        post.title = title
    if content:
        post.content = content

    db.session.commit()
    return jsonify(post.to_dict()), 200


@posts_bp.route('/<int:post_id>', methods=['DELETE'])
@jwt_required()
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    _authorize_post_action(post)

    db.session.delete(post)
    db.session.commit()
    return jsonify({"message": "Post deleted"}), 200
```

---

### models/user.py

```python
# User model
from database.db import db
from datetime import datetime

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
```

---

### models/post.py

```python
"""
Post model
"""
from database.db import db
from datetime import datetime


class Post(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "content": self.content,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
```
