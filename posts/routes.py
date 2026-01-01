from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from database.db import db
from postly.models.post import Post 

posts_bp = Blueprint("posts", __name__, url_prefix="/posts") 

# ====================
# CREATE POST
# ====================
@posts_bp.route("", methods=["POST"])
@jwt_required()
def create_post():
    identity = get_jwt_identity()
    
    # Safely handle if identity is a dict (new way) or int (old way)
    if isinstance(identity, dict):
        user_id = identity.get("id")
    else:
        user_id = identity
    
    data = request.json
    content = data.get("content")
    
    if not content:
        return jsonify({"error": "Post cannot be empty"}), 400
    
    new_post = Post(content=content, user_id=user_id)
    db.session.add(new_post)
    db.session.commit()
    return jsonify({"message": "Post created"}), 201

# ====================
# GET ALL POSTS
# ==================
@posts_bp.route("", methods=["GET"]) 
def get_posts():
    # Fetch posts and convert to list of dictionaries
    posts_query = Post.query.order_by(Post.id.desc()).all() 
    
    result = [] 
    for p in posts_query: 
        result.append({
            "id": p.id,
            "content": p.content, 
            "user_id": p.user_id
        })
        
    return jsonify(result), 200

# ====================
# DELETE POST
# ====================
@posts_bp.route("/<int:post_id>", methods=["DELETE"])
@jwt_required()
def delete_post(post_id):
    identity = get_jwt_identity()
    user_id = int(identity) # Based on our last fix
    
    post = Post.query.get_or_404(post_id)
    
    # Security check: Only the author can delete
    if post.user_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403
    
    db.session.delete(post)
    db.session.commit()
    return jsonify({"message": "Post deleted"}), 200

# ====================
# UPDATE POST
# ====================
@posts_bp.route("/<int:post_id>", methods=["PUT"])
@jwt_required()
def update_post(post_id):
    identity = get_jwt_identity()
    user_id = int(identity)
    
    post = Post.query.get_or_404(post_id)
    
    if post.user_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    new_content = data.get("content")
    
    if not new_content:
        return jsonify({"error": "Content cannot be empty"}), 400
        
    post.content = new_content
    db.session.commit()
    return jsonify({"message": "Post updated"}), 200