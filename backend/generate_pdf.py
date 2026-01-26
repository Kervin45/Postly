#!/usr/bin/env python3
"""Generate a PDF with all project source files"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Preformatted, Table, TableStyle
from reportlab.lib import colors
from datetime import datetime
import os

# Define file list with their paths and content
files_data = [
    ("app.py", """from flask import Flask, render_template
from flask_jwt_extended import JWTManager

# Always use package-absolute imports when running as `python -m postly.app`
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
    app.run(debug=True)"""),
    ("config.py", """# Configuration settings
import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = "your-secret-key"
    JWT_SECRET_KEY = "your-jwt-secret-key"
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'post.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False"""),
    ("requirements.txt", """# Project dependencies
flask
flask-jwt-extended
flask-sqlalchemy
werkzeug
python-dotenv
gunicorn"""),
    ("models/user.py", """from postly.database.db import db
from werkzeug.security import generate_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    posts = db.relationship("Post", back_populates="user", cascade="all, delete-orphan")"""),
    ("models/post.py", """from postly.database.db import db



class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship("User", back_populates="posts")"""),
    ("auth/routes.py", """from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from werkzeug.security import check_password_hash, generate_password_hash
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

    # 🔴 IMPORTANT: identity MUST be dict
    access_token = create_access_token(identity={
        "id": user.id,
        "username": user.username
    })

    return jsonify({
        "access_token": access_token,
        "username": user.username
    }), 200"""),
    ("auth/utils.py", """# Authentication utilities
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password):
    return generate_password_hash(password)

def verify_password(password, password_hash):
    return check_password_hash(password_hash, password)"""),
    ("posts/routes.py", """from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from database.db import db
from models.post import Post

posts_bp = Blueprint("posts", __name__, url_prefix="/posts")


# =========================
# CREATE POST
# =========================
@posts_bp.route("", methods=["POST"])
@jwt_required()
def create_post():
    identity = get_jwt_identity()   # {'id': x, 'username': y}
    user_id = identity["id"]

    data = request.json
    content = data.get("content")

    if not content:
        return jsonify({"error": "Post cannot be empty"}), 400

    post = Post(
        content=content,
        user_id=user_id
    )

    db.session.add(post)
    db.session.commit()

    return jsonify({"message": "Post created"}), 201


# =========================
# GET ALL POSTS
# =========================
@posts_bp.route("", methods=["GET"])
def get_posts():
    posts = Post.query.order_by(Post.id.desc()).all()

    result = []
    for p in posts:
        result.append({
            "id": p.id,
            "content": p.content,
            "user_id": p.user_id
        })

    return jsonify(result), 200"""),
    ("database/db.py", """from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()"""),
    ("static/style.css", """body{font-family:Arial,Helvetica,sans-serif;background:#f7f7f8;color:#222;margin:0;padding:0}
.container{max-width:720px;margin:32px auto;padding:20px;background:#fff;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,.05)}
form label{display:block;margin-bottom:12px}
input[type=text],input[type=email],input[type=password],textarea{width:100%;padding:8px;border:1px solid #ddd;border-radius:4px}
button{background:#007bff;color:#fff;border:none;padding:8px 12px;border-radius:4px;cursor:pointer}
article{border-top:1px solid #eee;padding:12px 0}
small{color:#666}"""),
    ("templates/index.html", """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Postly</title>
</head>
<body>
<h2>Welcome to Postly</h2>
<button onclick="window.location.href='/register-ui'">Register</button>
<button onclick="window.location.href='/login-ui'">Login</button>
</body>
</html>"""),
    ("templates/login.html", """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Login</title>
</head>
<body>
<h2>Login</h2>
<input id="email" placeholder="Email">
<input id="password" type="password" placeholder="Password">
<button id="login-btn">Login</button>
<p id="msg"></p>

<script>
document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("login-btn").addEventListener("click", async () => {
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;
        const msg = document.getElementById("msg");

        if(!email || !password){
            msg.innerText = "Fill all fields";
            msg.style.color = "red";
            return;
        }

        try{
            const res = await fetch("/auth/login", {
                method: "POST",
                headers: {"Content-Type":"application/json"},
                body: JSON.stringify({email,password})
            });
            const data = await res.json();

            if(!res.ok){
                msg.innerText = data.error || "Login failed";
                msg.style.color = "red";
            } else {
                localStorage.setItem("token", data.access_token);
                localStorage.setItem("username", data.username);
                window.location.href="/posts-ui";
            }
        }catch(err){
            msg.innerText = "Server error";
            msg.style.color = "red";
            console.error(err);
        }
    });
});
</script>
</body>
</html>"""),
    ("templates/register.html", """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Register</title>
</head>
<body>
<h2>Register</h2>
<input id="username" placeholder="Username">
<input id="email" placeholder="Email">
<input id="password" type="password" placeholder="Password">
<button id="register-btn">Sign Up</button>
<p id="msg"></p>

<script>
document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("register-btn").addEventListener("click", async () => {
        const username = document.getElementById("username").value;
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;
        const msg = document.getElementById("msg");

        if(!username || !email || !password) {
            msg.innerText = "Fill all fields";
            msg.style.color = "red";
            return;
        }

        try {
            const res = await fetch("/auth/register", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({username,email,password})
            });
            const data = await res.json();
            if(res.ok){
                msg.innerText = data.message;
                msg.style.color = "green";
            } else {
                msg.innerText = data.error;
                msg.style.color = "red";
            }
        } catch(err){
            msg.innerText = "Server error";
            msg.style.color = "red";
            console.error(err);
        }
    });
});
</script>
</body>
</html>"""),
    ("templates/posts.html", """<!DOCTYPE html>
<html>
<head>
    <title>Posts</title>
</head>
<body>

<h2>Create Post</h2>

<textarea id="content" placeholder="Write something..."></textarea><br><br>
<button onclick="createPost()">Post</button>

<hr>

<h2>Feed</h2>
<ul id="feed"></ul>

<script>
const token = localStorage.getItem("token");

if (!token) {
    window.location.href = "/login-ui";
}

async function createPost() {
    const content = document.getElementById("content").value;

    if (!content) {
        alert("Post cannot be empty");
        return;
    }

    const res = await fetch("/posts", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token
        },
        body: JSON.stringify({ content })
    });

    if (!res.ok) {
        alert("Post failed");
        return;
    }

    document.getElementById("content").value = "";
    loadPosts();
}

async function loadPosts() {
    const res = await fetch("/posts");
    const posts = await res.json();

    const feed = document.getElementById("feed");
    feed.innerHTML = "";

    posts.forEach(p => {
        const li = document.createElement("li");
        li.innerHTML = `<b>User ${p.user_id}</b>: ${p.content}`;
        feed.appendChild(li);
    });
}

loadPosts();
</script>

</body>
</html>"""),
]

# Create PDF
pdf_file = "Postly_Project_Code.pdf"
doc = SimpleDocTemplate(pdf_file, pagesize=letter)
styles = getSampleStyleSheet()

# Custom styles
title_style = ParagraphStyle(
    'CustomTitle',
    parent=styles['Heading1'],
    fontSize=24,
    textColor=colors.HexColor('#1f77b4'),
    spaceAfter=6,
    spaceBefore=6,
)

file_header_style = ParagraphStyle(
    'FileHeader',
    parent=styles['Heading2'],
    fontSize=12,
    textColor=colors.HexColor('#2ca02c'),
    spaceAfter=6,
    spaceBefore=12,
    borderPadding=6,
    borderColor=colors.HexColor('#cccccc'),
    borderWidth=1,
)

content = []

# Title page
content.append(Paragraph("Postly Project", title_style))
content.append(Paragraph("Complete Source Code", styles['Heading2']))
content.append(Spacer(1, 0.3*inch))
content.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", styles['Normal']))
content.append(PageBreak())

# Table of contents
content.append(Paragraph("Table of Contents", styles['Heading1']))
for i, (filename, _) in enumerate(files_data, 1):
    content.append(Paragraph(f"{i}. {filename}", styles['Normal']))
content.append(PageBreak())

# Add files
for filename, code_content in files_data:
    content.append(Paragraph(f"📄 {filename}", file_header_style))
    
    # Format code with monospace font
    code_style = ParagraphStyle(
        'Code',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        textColor=colors.HexColor('#333333'),
        leftIndent=12,
    )
    
    # Escape special characters for XML/Paragraph compatibility
    escaped_content = code_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    
    # Split code into chunks if too long
    lines = escaped_content.split('\n')
    for line in lines:
        if line.strip():
            content.append(Paragraph(line or " ", code_style))
        else:
            content.append(Spacer(1, 0.05*inch))
    
    content.append(Spacer(1, 0.2*inch))
    content.append(Paragraph("_" * 80, styles['Normal']))
    content.append(PageBreak())

# Build PDF
doc.build(content)
print(f"✅ PDF generated: {pdf_file}")
print(f"📍 Location: {os.path.abspath(pdf_file)}")
