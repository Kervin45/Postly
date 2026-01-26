from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from database.db import db
from models.post import Post
from models.user import User

posts_bp = Blueprint('posts', __name__)

@posts_bp.route('', methods=['POST'])
@jwt_required()
def create_post():
    try:
        # Get identity - should be string (user ID)
        user_id_str = get_jwt_identity()
        print(f"User ID from token: {user_id_str}")
        
        # Convert to int
        user_id = int(user_id_str)
        
        # Get post content
        data = request.get_json()
        print(f"Request data: {data}")
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        content = data.get('content')
        
        if not content or not str(content).strip():
            return jsonify({"error": "Post content is required"}), 400
        
        content = str(content).strip()
        
        # Check if user exists
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Create new post
        new_post = Post(
            content=content,
            user_id=user_id
        )
        
        db.session.add(new_post)
        db.session.commit()
        
        return jsonify({
            "message": "Post created successfully",
            "post": {
                "id": new_post.id,
                "content": new_post.content,
                "user_id": new_post.user_id,
                "username": user.username
            }
        }), 201
        
    except ValueError:
        return jsonify({"error": "Invalid user ID in token"}), 401
    except Exception as e:
        print(f"Error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": f"Failed to create post: {str(e)}"}), 500

# Keep the rest of your routes.py as is...

@posts_bp.route('', methods=['GET'])
def get_posts():
    try:
        posts = Post.query.order_by(Post.created_at.desc()).all()
        
        posts_data = []
        for post in posts:
            posts_data.append({
                "id": post.id,
                "content": post.content,
                "username": post.author.username if post.author else "Anonymous",
                "user_id": post.user_id,
                "created_at": post.created_at.strftime('%b %d, %H:%M') if post.created_at else ''
            })
        
        return jsonify(posts_data), 200
        
    except Exception as e:
        return jsonify({"error": f"Failed to fetch posts: {str(e)}"}), 500

# Add these routes for update and delete
@posts_bp.route('/<int:post_id>', methods=['PUT'])
@jwt_required()
def update_post(post_id):
    try:
        identity = get_jwt_identity()
        if isinstance(identity, str):
            user_id = int(identity)
        elif isinstance(identity, dict):
            user_id = identity.get("id")
            if isinstance(user_id, str):
                user_id = int(user_id)
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        content = data.get('content')
        if not content or not content.strip():
            return jsonify({"error": "Post content is required"}), 400
        
        post = Post.query.get(post_id)
        if not post:
            return jsonify({"error": "Post not found"}), 404
            
        if post.user_id != user_id:
            return jsonify({"error": "Unauthorized to edit this post"}), 403
        
        post.content = content.strip()
        db.session.commit()
        
        return jsonify({"message": "Post updated successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to update post: {str(e)}"}), 500

@posts_bp.route('/<int:post_id>', methods=['DELETE'])
@jwt_required()
def delete_post(post_id):
    try:
        identity = get_jwt_identity()
        if isinstance(identity, str):
            user_id = int(identity)
        elif isinstance(identity, dict):
            user_id = identity.get("id")
            if isinstance(user_id, str):
                user_id = int(user_id)
        
        post = Post.query.get(post_id)
        if not post:
            return jsonify({"error": "Post not found"}), 404
            
        if post.user_id != user_id:
            return jsonify({"error": "Unauthorized to delete this post"}), 403
        
        db.session.delete(post)
        db.session.commit()
        
        return jsonify({"message": "Post deleted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to delete post: {str(e)}"}), 500