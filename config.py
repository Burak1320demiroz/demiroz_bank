import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    ADMIN_CREDENTIALS = {
        'username': os.environ.get('ADMIN_USER'),
        'password_hash': os.environ.get('ADMIN_PASSWORD_HASH')
    }
    SESSION_COOKIE_SECURE = True
    PERMANENT_SESSION_LIFETIME = 86400  # 1 gün saniye cinsinden