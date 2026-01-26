import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = 'your-secret-key-change-this-in-production'
    JWT_SECRET_KEY = 'your-jwt-secret-key-change-this-too'
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(basedir, 'post.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False