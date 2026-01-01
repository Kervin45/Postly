from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from werkzeug.security import check_password_hash, generate_password_hash
# Package-absolute imports
from database.db import db
from models.user import User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    
    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 400
    
    user = User(
        username=username,
        email=email,
        password=generate_password_hash(password)
    )
    
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # identity MUST be a dictionary for your frontend logic
    access_token = create_access_token(identity=str(user.id)) 
    
    return jsonify({
        "access_token": access_token,
        "username": user.username
    }), 200