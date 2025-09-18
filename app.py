"""
Demiröz Bank Flask Uygulaması
Gelişmiş güvenlik önlemleri içeren banka yönetim sistemi
"""

from flask import Flask, render_template, request, redirect, url_for, session, make_response, send_from_directory, flash, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import os
import uuid
import time
from datetime import timedelta, datetime
import logging
from functools import wraps
import redis
import sqlite3
import subprocess
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from models import db, User, Transaction, Message, Notification, UserRecommendation
import secrets
import string
import requests
import random
from werkzeug.utils import secure_filename
import html
from urllib.parse import urlparse, quote
import base64
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash

# Flask uygulaması oluşturma
app = Flask(__name__)
app.env = 'production'  # Production modunda çalıştır
DEBUG_MODE = False
r = redis.Redis(host='localhost', port=6379)

# Temel yapılandırma ayarları
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config.update(
    # Oturum Yönetimi Ayarları
    PERMANENT_SESSION_LIFETIME=timedelta(days=1),
    SESSION_COOKIE_SECURE=True,    # Production için True
    SESSION_COOKIE_HTTPONLY=True,  # XSS koruması
    SESSION_COOKIE_SAMESITE='Strict', # CSRF koruması
    SESSION_COOKIE_NAME='demiroz_bank_session',
    
    # Ek Güvenlik Ayarları
    PREFERRED_URL_SCHEME='https',  # Production için https
    JSONIFY_PRETTYPRINT_REGULAR=True,  # Development için True
    UPLOAD_FOLDER='uploads',  # Dosya yükleme klasörü
    SQLALCHEMY_DATABASE_URI='sqlite:///bank.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    
    # Rate Limiting Ayarları
    RATELIMIT_DEFAULT="50 per minute",  # Varsayılan limit
    RATELIMIT_STORAGE_URL="memory://",  # Bellek tabanlı limit
    RATELIMIT_STRATEGY="fixed-window",  # Sabit pencere stratejisi
    RATELIMIT_HEADERS_ENABLED=True,     # Rate limit başlıklarını göster
    RATELIMIT_HEADERS_RESET=True,       # Limit sıfırlandığında başlık göster
    RATELIMIT_HEADERS_RETRY_AFTER=True  # Retry-After başlığını göster
)

# Upload klasörünü oluştur
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Avatar yükleme klasörünü oluştur
AVATAR_FOLDER = os.path.join('static', 'avatars')
os.makedirs(AVATAR_FOLDER, exist_ok=True)

# Redis ve Rate Limiter Yapılandırması
try:
    # Redis bağlantısı (Rate limiting ve oturum yönetimi için)
    redis_client = redis.Redis(
        host='localhost',
        port=6379,
        db=0,
        socket_connect_timeout=3,  # 3 saniye bağlantı zaman aşımı
        socket_timeout=5,          # 5 saniye işlem zaman aşımı
        decode_responses=True,
        health_check_interval=30   # Bağlantı sağlık kontrolü
    )
    redis_client.ping()  # Bağlantı testi
    
    # Rate limiter'ı aktif et
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        storage_uri="memory://",
        default_limits=["100 per minute"],  # Güvenli limit
        strategy="fixed-window",
        enabled=True  # Rate limiter'ı aktif et
    )
except (redis.ConnectionError, redis.TimeoutError) as e:
    logging.warning(f"Redis bağlantı hatası: {str(e)} - Bellek deposuna geçiliyor...")
    # Rate limiter'ı aktif et
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        storage_uri="memory://",
        default_limits=["100 per minute"],  # Güvenli limit
        enabled=True  # Rate limiter'ı aktif et
    )

# Loglama Yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bank_app.log'),
        logging.StreamHandler()
    ]
)

# Admin bilgileri (Gerçek uygulamada veritabanı kullanılmalı)
ADMIN_FIXED_PASSWORD = 'DEMIROZctf2024!_BuCokGucluBirSabitAdminSifresi_70Karakterli_!@#1234567890'
ADMIN_CREDENTIALS = {
    'username': 'admin',
    'password_hash': bcrypt.hashpw(ADMIN_FIXED_PASSWORD.encode('utf-8'), bcrypt.gensalt(rounds=12))
}

# Güvenlik ayarları
SESSION_TIMEOUT = 1800  # 30 dakika

# IP bazlı engelleme için Redis kullanımı
blocked_ips = {}  # {ip: {'blocked_until': timestamp}}
ip_request_count = {}  # {ip: {'count': count, 'last_reset': timestamp}}
failed_attempts = {}  # {ip: {'count': count, 'timestamp': timestamp}}

def is_ip_blocked(ip):
    """IP adresi engellenmiş mi kontrol et"""
    if ip in blocked_ips:
        if int(time.time()) < blocked_ips[ip]['blocked_until']:
            return True
        else:
            # Engelleme süresi dolmuş, kaldır
            del blocked_ips[ip]
    return False

def block_ip(ip):
    """IP adresini engelle"""
    blocked_ips[ip] = {
        'blocked_until': int(time.time()) + 3600  # 1 saat engelle
    }
    logging.warning(f"IP adresi engellendi: {ip}")

def check_ip_rate(ip):
    """IP bazlı istek sayısını kontrol et"""
    current_time = int(time.time())
    
    # IP için istek sayısını kontrol et
    if ip not in ip_request_count:
        ip_request_count[ip] = {'count': 0, 'last_reset': current_time}
    
    # Her dakika sıfırla
    if current_time - ip_request_count[ip]['last_reset'] > 60:
        ip_request_count[ip] = {'count': 0, 'last_reset': current_time}
    
    # İstek sayısını artır
    ip_request_count[ip]['count'] += 1
    
    # 100 istek/dakika limiti
    if ip_request_count[ip]['count'] > 100:
        block_ip(ip)
        return False
    
    return True

# Decorator Tanımları
def admin_required(f):
    """Yalnızca admin kullanıcıların erişimine izin veren decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Session kontrolü
        if not session.get('is_admin'):
            logging.warning("Yetkisiz erişim denemesi")
            return render_template('error.html', 
                                title='Erişim Reddedildi',
                                message='Yetkisiz erişim denemesi'), 403
        return f(*args, **kwargs)
    return decorated_function

def security_headers(f):
    """Güvenlik başlıklarını ekleyen decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        # Modern güvenlik başlıkları
        response.headers.update({
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
            'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
            'Permissions-Policy': "geolocation=(), microphone=()"
        })
        return response
    return decorated_function

# Veritabanı ve login yöneticisini başlat
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Veritabanı bağlantısı
def get_db():
    """SQLite veritabanı bağlantısı oluşturur"""
    conn = sqlite3.connect('bank.db')
    conn.row_factory = sqlite3.Row
    return conn

# Veritabanını başlat
def init_db():
    with app.app_context():
        # Tüm tabloları sil ve yeniden oluştur
        db.drop_all()
        db.create_all()
        
        # Admin kullanıcısını oluştur
        admin_user = User(
            username='admin',
            password_hash=ADMIN_CREDENTIALS['password_hash'].decode('utf-8'),
            account_number=''.join(secrets.choice(string.digits) for _ in range(16)),
            balance=1000000.0,  # Admin için yüksek bakiye
            is_admin=True
        )
        db.session.add(admin_user)
        
        # Belirtilen kullanıcıyı ekle
        burak_password_hash = bcrypt.hashpw('Burakdemiroz1234567+'.encode('utf-8'), bcrypt.gensalt())
        burak_user = User(
            username='burak',
            password_hash=burak_password_hash.decode('utf-8'),
            account_number=''.join(secrets.choice(string.digits) for _ in range(16)),
            balance=5000.0,  # Başlangıç bakiyesi
            is_admin=False
        )
        db.session.add(burak_user)
        
        # Admin bilgilerini güvenli şekilde sakla (CTF flag'i kaldırıldı)
        with get_db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS admin_secrets (
                    id INTEGER PRIMARY KEY,
                    username TEXT,
                    password TEXT,
                    secret_key TEXT
                )
            """)
            conn.execute("""
                INSERT INTO admin_secrets (username, password, secret_key)
                VALUES (?, ?, ?)
            """, ('admin', ADMIN_FIXED_PASSWORD, 'SECURE_ADMIN_KEY_REMOVED_FOR_SECURITY'))
            conn.commit()
        
        # 20 rastgele müşteri oluştur
        first_names = ['Ahmet', 'Mehmet', 'Ayşe', 'Fatma', 'Ali', 'Veli', 'Zeynep', 'Elif', 'Mustafa', 'Hasan', 
                      'Hüseyin', 'Emine', 'Hatice', 'İbrahim', 'Osman', 'Kemal', 'Sultan', 'Meryem', 'Ramazan', 'Yusuf']
        last_names = ['Yılmaz', 'Kaya', 'Demir', 'Çelik', 'Şahin', 'Yıldız', 'Özdemir', 'Arslan', 'Doğan', 'Kılıç',
                     'Aydın', 'Öztürk', 'Şen', 'Erdoğan', 'Aktaş', 'Kurt', 'Koç', 'Aslan', 'Çetin', 'Güneş']
        
        for i in range(20):
            username = f"{first_names[i].lower()}{last_names[i].lower()}"
            password = ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?") for _ in range(20))
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            account_number = ''.join(secrets.choice(string.digits) for _ in range(16))
            balance = random.uniform(1000.0, 100000.0)  # Rastgele bakiye
            
            new_user = User(
                username=username,
                password_hash=password_hash.decode('utf-8'),
                account_number=account_number,
                balance=balance
            )
            db.session.add(new_user)
        
        db.session.commit()

# Veritabanını başlat
init_db()

# Debug modu (Güvenli)
DEBUG_MODE = False  # Üretimde her zaman False olmalı

@app.errorhandler(404)
def page_not_found(e):
    """404 Sayfa bulunamadı hatası"""
    logging.warning(f"404 hatası: {request.path}")
    return render_template('error.html',
                        title='Sayfa Bulunamadı',
                        message='Aradığınız sayfa mevcut değil'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """500 Sunucu hatası"""
    logging.error(f"Sunucu hatası: {str(e)}")
    return render_template('error.html',
                        title='Sunucu Hatası',
                        message='Bir hata oluştu'), 500

# Debug endpoint'i kaldırıldı - Güvenlik nedeniyle

@app.route('/error')
def generate_error():
    """Hata oluştur (Güvenli)"""
    return 'Bu endpoint devre dışı bırakıldı', 403

@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    """Avatar yükleme işlemi (Güvenli)"""
    if 'avatar' not in request.files:
        flash('Dosya seçilmedi', 'error')
        return redirect(url_for('profile'))
    
    file = request.files['avatar']
    if file.filename == '':
        flash('Dosya seçilmedi', 'error')
        return redirect(url_for('profile'))
    
    # Güvenli dosya uzantısı kontrolü
    allowed_extensions = {'jpg', 'jpeg', 'png', 'gif'}
    if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        flash('Geçersiz dosya türü', 'error')
        return redirect(url_for('profile'))
    
    # Güvenli dosya adı oluştur
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_filename = f"{timestamp}_{filename}"
    
    # Dosyayı kaydet
    file_path = os.path.join(AVATAR_FOLDER, safe_filename)
    file.save(file_path)
    
    # Kullanıcının avatar bilgisini güncelle
    current_user.avatar = safe_filename
    db.session.commit()
    
    flash('Profil fotoğrafı başarıyla güncellendi', 'success')
    return redirect(url_for('profile'))

@app.route('/fetch_url', methods=['POST'])
@login_required
def fetch_url():
    """SSRF korumalı URL fetch (Güvenli)"""
    url = request.form.get('url')
    if not url:
        return 'URL gerekli', 400
    
    # URL güvenlik kontrolü
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme in ['http', 'https']:
            return 'Sadece HTTP ve HTTPS protokolleri desteklenir', 400
            
        # İç IP adreslerini engelle
        hostname = parsed_url.hostname
        if hostname in ['localhost', '127.0.0.1', '::1'] or \
           hostname.startswith('192.168.') or \
           hostname.startswith('10.') or \
           hostname.startswith('172.') or \
           hostname.startswith('169.254.'):
            return 'İç IP adreslerine erişim engellendi', 403
        
        # URL'yi fetch et (timeout ve max size ile)
        response = requests.get(url, timeout=5, stream=True)
        response.raise_for_status()
        
        # Maksimum boyut kontrolü (1MB)
        content_length = int(response.headers.get('content-length', 0))
        if content_length > 1024 * 1024:
            return 'Dosya boyutu çok büyük', 413
            
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"URL fetch hatası: {str(e)}")
        return 'URL erişim hatası', 500
    except Exception as e:
        logging.error(f"Beklenmeyen hata: {str(e)}")
        return 'Bir hata oluştu', 500

# Rotalar
@app.route('/')
@security_headers
def home():
    """Ana sayfa"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Login için rate limiting
@security_headers
def login():
    """Kullanıcı giriş işlemini işler"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            logging.info(f"Kullanıcı girişi: {username}")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        
        flash('Geçersiz kullanıcı adı veya şifre', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Yeni kullanıcı kontrolü
    is_new_user = current_user.is_new_user
    if is_new_user:
        # İlk girişte karşılama mesajlarını göster
        welcome_messages = Notification.query.filter_by(
            user_id=current_user.id,
            type='welcome'
        ).all()
        
        # Önerileri getir
        recommendations = UserRecommendation.query.filter_by(
            user_id=current_user.id,
            is_completed=False
        ).all()
        
        # Yeni kullanıcı flag'ini güncelle
        current_user.is_new_user = False
        db.session.commit()
        
        return render_template('dashboard.html',
                             is_new_user=True,
                             welcome_messages=welcome_messages,
                             recommendations=recommendations)
    
    # Normal dashboard içeriği
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).limit(5).all()
    return render_template('dashboard.html', transactions=transactions)

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")  # Transfer için rate limiting
def transfer():
    if request.method == 'POST':
        try:
            recipient_id = request.form.get('recipient')
            amount_str = request.form.get('amount', '')
            description = request.form.get('description', '')
            
            # Input validation
            if not recipient_id or not amount_str:
                return render_template('transfer.html', error='Tüm alanlar zorunludur', users=User.query.all(), current_user_id=current_user.id)
            
            # Amount validation
            try:
                amount = float(amount_str)
            except (ValueError, TypeError):
                return render_template('transfer.html', error='Geçersiz tutar formatı', users=User.query.all(), current_user_id=current_user.id)
            
            if amount <= 0:
                return render_template('transfer.html', error='Transfer tutarı pozitif olmalıdır', users=User.query.all(), current_user_id=current_user.id)
            
            if amount > 100000:  # Maksimum transfer limiti
                return render_template('transfer.html', error='Transfer tutarı çok yüksek', users=User.query.all(), current_user_id=current_user.id)
            
            # Description validation
            if len(description) > 200:
                return render_template('transfer.html', error='Açıklama çok uzun', users=User.query.all(), current_user_id=current_user.id)
            
            # HTML escape description
            description = html.escape(description)
            
            recipient = User.query.get(recipient_id)
            if not recipient:
                return render_template('transfer.html', error='Alıcı bulunamadı', users=User.query.all(), current_user_id=current_user.id)
            
            if recipient.id == current_user.id:
                return render_template('transfer.html', error='Kendinize transfer yapamazsınız', users=User.query.all(), current_user_id=current_user.id)
            
            if current_user.balance < amount:
                return render_template('transfer.html', error='Yetersiz bakiye', users=User.query.all(), current_user_id=current_user.id)
                
        except Exception as e:
            logging.error(f"Transfer validation hatası: {str(e)}")
            return render_template('transfer.html', error='Geçersiz veri', users=User.query.all(), current_user_id=current_user.id)
        
        # Transfer işlemini gerçekleştir
        current_user.balance -= amount
        recipient.balance += amount
        
        # İşlem kayıtlarını oluştur
        sender_transaction = Transaction(
            user_id=current_user.id,
            amount=-amount,
            description=f'Transfer: {recipient.username} - {description}',
            transaction_type='transfer'
        )
        
        recipient_transaction = Transaction(
            user_id=recipient.id,
            amount=amount,
            description=f'Transfer: {current_user.username} - {description}',
            transaction_type='transfer'
        )
        
        db.session.add(sender_transaction)
        db.session.add(recipient_transaction)
        db.session.commit()
        
        return render_template('transfer.html', success='Transfer başarıyla gerçekleştirildi', users=User.query.all(), current_user_id=current_user.id)
    
    return render_template('transfer.html', users=User.query.all(), current_user_id=current_user.id)

@app.route('/transactions')
@login_required
def transactions():
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    return render_template('transactions.html', transactions=user_transactions)

@app.route('/profile')
@login_required
def profile():
    user = User.query.get(current_user.id)
    return render_template('profile.html', user=user)

@app.route('/admin')
@admin_required
@security_headers
def admin():
    """Admin kontrol paneli - Güvenli versiyon"""
    # Ek güvenlik kontrolleri
    if not current_user.is_admin:
        logging.warning(f"Yetkisiz admin erişim denemesi: {current_user.username}")
        return render_template('error.html', 
                            title='Erişim Reddedildi',
                            message='Bu sayfaya erişim yetkiniz yok'), 403
    
    # IP adresi kontrolü (sadece localhost)
    if request.remote_addr not in ['127.0.0.1', '::1']:
        logging.warning(f"Admin paneli dış IP erişim denemesi: {request.remote_addr}")
        return render_template('error.html',
                            title='Erişim Reddedildi', 
                            message='Admin paneline sadece yerel erişim izin verilir'), 403
    
    # User-Agent kontrolü
    if 'user_agent' in session and session['user_agent'] != request.user_agent.string:
        logging.warning("User-Agent değişikliği tespit edildi!")
        session.clear()
        return redirect(url_for('home'))
    
    # İstatistikleri hesapla
    total_users = User.query.count()
    total_transactions = Transaction.query.count()
    total_balance = db.session.query(db.func.sum(User.balance)).scalar() or 0
    
    # Son aktiviteleri al
    recent_activities = Transaction.query\
        .join(User)\
        .order_by(Transaction.timestamp.desc())\
        .limit(10)\
        .all()
    
    activities = []
    for transaction in recent_activities:
        activities.append({
            'username': transaction.user.username,
            'action': f"{transaction.transaction_type}: {transaction.amount} TL",
            'timestamp': transaction.timestamp.strftime('%d/%m/%Y %H:%M')
        })
    
    return render_template('admin.html',
                        title='Admin Paneli',
                        total_users=total_users,
                        total_transactions=total_transactions,
                        total_balance=total_balance,
                        recent_activities=activities)

@app.route('/logout')
@admin_required
def logout():
    """Güvenli çıkış işlemi"""
    logging.info(f"Çıkış yapıldı: {session.get('username')}, IP: {request.remote_addr}")
    session.clear()
    response = make_response(redirect(url_for('home')))
    # Tüm çerezleri temizle
    response.delete_cookie('demiroz_bank_session')
    response.delete_cookie('session')
    return response

# Her istek öncesi güvenlik kontrolleri
@app.before_request
def before_request():
    """Her istek öncesi güvenlik kontrolleri"""
    # HTTPS yönlendirmesi (üretimde)
    if not request.is_secure and app.env == 'production':
        return redirect(request.url.replace('http://', 'https://'))
    
    # Oturum süresi kontrolü
    if 'session_expires' in session:
        if int(time.time()) > session['session_expires']:
            session.clear()
            return redirect(url_for('home'))
    
    # User-Agent kontrolü
    if 'user_agent' in session and session['user_agent'] != request.user_agent.string:
        logging.warning("User-Agent değişikliği tespit edildi!")
        session.clear()
        return redirect(url_for('home'))

# Veritabanı tablolarını oluştur
def init_db():
    with app.app_context():
        db.create_all()
        
        # Test kullanıcılarını oluştur
        test_users = [
            ('ahmet', 'Test123!@#$%^&*()_+-=[]{}|;:,.<>?'),
            ('mehmet', 'Test456!@#$%^&*()_+-=[]{}|;:,.<>?'),
            ('ayse', 'Test789!@#$%^&*()_+-=[]{}|;:,.<>?')
        ]
        
        for username, password in test_users:
            # Kullanıcı zaten var mı kontrol et
            user = User.query.filter_by(username=username).first()
            if not user:
                # Şifreyi bcrypt ile hashle
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                # Rastgele hesap numarası oluştur
                account_number = ''.join(secrets.choice(string.digits) for _ in range(16))
                
                new_user = User(
                    username=username,
                    password_hash=password_hash.decode('utf-8'),
                    account_number=account_number,
                    balance=1000.0  # Başlangıç bakiyesi
                )
                db.session.add(new_user)
        
        db.session.commit()

# Veritabanını başlat
init_db()

# Yeni rotalar ekle
@app.route('/search')
@admin_required
@security_headers
def search():
    """SSTI korumalı arama"""
    query = request.args.get('q', '')
    # HTML escape kullan
    query = html.escape(query)
    return render_template('search.html', query=query)

@app.route('/upload', methods=['GET', 'POST'])
@security_headers
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'Dosya seçilmedi', 400
        file = request.files['file']
        if file.filename == '':
            return 'Dosya seçilmedi', 400
        
        # Güvenli dosya uzantısı kontrolü
        allowed_extensions = {'jpg', 'jpeg', 'png', 'gif'}
        if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            return 'Geçersiz dosya türü', 400
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # SSRF koruması
        if request.form.get('process'):
            try:
                url = request.form.get('url', '')
                if url:
                    parsed_url = urlparse(url)
                    if parsed_url.scheme not in ['http', 'https']:
                        return 'Sadece HTTP ve HTTPS protokolleri desteklenir', 400
                    
                    # İç IP adreslerini engelle
                    hostname = parsed_url.hostname
                    if hostname in ['localhost', '127.0.0.1', '::1'] or hostname.startswith('192.168.') or hostname.startswith('10.') or hostname.startswith('172.'):
                        return 'İç IP adreslerine erişim engellendi', 403
                    
                    response = requests.get(url, timeout=5)
                    return response.text
            except Exception as e:
                return str(e), 500
        
        return 'Dosya başarıyla yüklendi'
    return render_template('upload.html')

@app.route('/files/<path:filename>')
@security_headers
def get_file(filename):
    """Dosya indirme (Directory Traversal korumalı)"""
    # Path traversal kontrolü
    if '..' in filename or filename.startswith('/') or filename.startswith('\\'):
        return "Erişim engellendi", 403
    
    # Sadece izin verilen dosya türleri
    allowed_extensions = {'jpg', 'jpeg', 'png', 'gif'}
    if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return "Geçersiz dosya türü", 400
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# AWS WAF Simülasyonu (Güncel Sürüm - Tüm Güvenlik Önlemleri Aktif)
class AWSWAF:
    def __init__(self):
        self.version = "AWS-WAF-2023-12-01"  # Güncel AWS WAF sürümü
        self.blocked_patterns = [
            # SQL Injection Pattern'leri
            "SELECT.*FROM", "UNION.*SELECT", "DROP.*TABLE", "DELETE.*FROM", 
            "UPDATE.*SET", "INSERT.*INTO", "ALTER.*TABLE", "TRUNCATE.*TABLE",
            "EXEC.*SP_", "EXECUTE.*IMMEDIATE", "DECLARE.*@", "WAITFOR.*DELAY",
            
            # Path Traversal Pattern'leri
            "\.\./", "\.\.\\", "/\.\.", "\\\.\.", "\.\.%2f", "%2e%2e%2f",
            
            # SSRF Pattern'leri
            "file://", "gopher://", "dict://", "ldap://", "tftp://",
            "127.0.0.1", "localhost", "::1", "0.0.0.0",
            "192.168.", "10.", "172.", "169.254.",
            
            # XSS Pattern'leri
            "<script", "javascript:", "onerror=", "onload=", "onmouseover=",
            "alert(", "confirm(", "prompt(", "eval(", "document.cookie",
            
            # Command Injection Pattern'leri
            ";", "|", "&", ">", "<", "`", "$", "(", ")", "{", "}",
            
            # Diğer Tehlikeli Pattern'ler
            "php://", "data://", "expect://", "input://", "phar://"
        ]
    
    def check_request(self, request):
        """AWS WAF kontrolü - Tüm güvenlik kontrolleri aktif"""
        # URL ve header'ları kontrol et
        for pattern in self.blocked_patterns:
            if pattern in request.url or pattern in str(request.headers):
                return False
        
        # JSON içeriğini kontrol et
        if request.is_json:
            data = request.get_json()
            if data:
                # Tüm JSON içeriğini string'e çevir ve kontrol et
                json_str = str(data)
                for pattern in self.blocked_patterns:
                    if pattern in json_str:
                        return False
        
        return True

# WAF instance'ı oluştur
waf = AWSWAF()

@app.route('/balance', methods=['GET', 'POST'])
@login_required
@security_headers
def check_balance():
    """Bakiye sorgulama - Güvenli versiyon (SQL Injection korumalı)"""
    if request.method == 'POST':
        try:
            # AWS WAF kontrolü
            if not waf.check_request(request):
                return jsonify({
                    'status': 'error',
                    'message': 'AWS WAF: Güvenlik ihlali tespit edildi'
                }), 403
            
            # JSON verisini al
            data = request.get_json()
            if not data:
                return jsonify({
                    'status': 'error',
                    'message': 'Geçersiz JSON verisi'
                }), 400
            
            # Sadece kullanıcı ID'sini kabul et
            user_id = data.get('user_id')
            if not user_id:
                return jsonify({
                    'status': 'error',
                    'message': 'Kullanıcı ID gerekli'
                }), 400
            
            # Kullanıcı ID'sini doğrula (sadece sayı)
            try:
                user_id = int(user_id)
            except (ValueError, TypeError):
                return jsonify({
                    'status': 'error',
                    'message': 'Geçersiz kullanıcı ID formatı'
                }), 400
            
            # Sadece kendi bilgilerini sorgulayabilir
            if user_id != current_user.id and not current_user.is_admin:
                return jsonify({
                    'status': 'error',
                    'message': 'Sadece kendi bilgilerinizi sorgulayabilirsiniz'
                }), 403
            
            # Güvenli parametreli sorgu kullan
            with get_db() as db_conn:
                cursor = db_conn.execute(
                    "SELECT id, username, account_number, balance FROM users WHERE id = ?", 
                    (user_id,)
                )
                result = cursor.fetchall()
            
            if not result:
                return jsonify({
                    'status': 'error',
                    'message': 'Kullanıcı bulunamadı'
                }), 404
            
            return jsonify({
                'status': 'success',
                'data': [dict(row) for row in result]
            })
            
        except Exception as e:
            logging.error(f"Bakiye sorgulama hatası: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Sunucu hatası'
            }), 500
    
    return render_template('balance.html')

# HTTP İstek Test Rotaları
@app.route('/test/get')
@security_headers
def test_get():
    """GET isteği testi"""
    # URL'den parametreleri al
    name = request.args.get('name', '')
    age = request.args.get('age', '')
    
    # İstek başlıklarını al
    headers = dict(request.headers)
    
    return render_template('test_get.html',
                        name=name,
                        age=age,
                        headers=headers)

@app.route('/test/post', methods=['GET', 'POST'])
@security_headers
def test_post():
    """POST isteği testi"""
    if request.method == 'POST':
        # Form verilerini al
        name = request.form.get('name', '')
        age = request.form.get('age', '')
        message = request.form.get('message', '')
        
        # JSON verisi varsa al
        json_data = request.get_json(silent=True)
        
        # İstek başlıklarını al
        headers = dict(request.headers)
        
        return render_template('test_post.html',
                            name=name,
                            age=age,
                            message=message,
                            json_data=json_data,
                            headers=headers,
                            method='POST')
    
    return render_template('test_post.html', method='GET')

@app.route('/test/api', methods=['GET', 'POST', 'PUT', 'DELETE'])
@security_headers
def test_api():
    """API istek testi"""
    # İstek metodunu al
    method = request.method
    
    # İstek verilerini al
    data = {
        'method': method,
        'args': dict(request.args),
        'form': dict(request.form),
        'json': request.get_json(silent=True),
        'headers': dict(request.headers),
        'cookies': dict(request.cookies)
    }
    
    return data

def validate_password(password, is_admin=False):
    """Şifre doğrulama fonksiyonu"""
    if is_admin:
        min_length = 70
    else:
        min_length = 20
    
    if len(password) < min_length:
        return False, f"Şifre en az {min_length} karakter olmalıdır"
    
    # Büyük harf kontrolü
    if not any(c.isupper() for c in password):
        return False, "Şifre en az bir büyük harf içermelidir"
    
    # Küçük harf kontrolü
    if not any(c.islower() for c in password):
        return False, "Şifre en az bir küçük harf içermelidir"
    
    # Rakam kontrolü
    if not any(c.isdigit() for c in password):
        return False, "Şifre en az bir rakam içermelidir"
    
    # Özel karakter kontrolü
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        return False, "Şifre en az bir özel karakter içermelidir"
    
    return True, "Şifre geçerli"

# Yeni kullanıcı karşılama mesajları
WELCOME_MESSAGES = [
    {
        'title': 'Hoş Geldiniz!',
        'message': 'Demiröz Bank ailesine katıldığınız için teşekkür ederiz. Size özel kampanyalar ve hizmetlerimizi keşfedin.',
        'type': 'welcome'
    },
    {
        'title': 'İlk İşlem İndirimi',
        'message': 'İlk kredi kartı başvurunuzda %50 indirim fırsatı sizi bekliyor!',
        'type': 'promo'
    },
    {
        'title': 'Güvenli Bankacılık',
        'message': 'Hesabınızı güvende tutmak için iki faktörlü doğrulamayı aktifleştirmeyi unutmayın.',
        'type': 'security'
    }
]

# Yeni kullanıcı önerileri
NEW_USER_RECOMMENDATIONS = [
    {
        'title': 'Kredi Kartı',
        'description': 'İlk kredi kartınızı alın, %10 nakit iade kazanın',
        'icon': 'credit-card',
        'type': 'card'
    },
    {
        'title': 'Bireysel Emeklilik',
        'description': 'Emeklilik planınızı oluşturun, devlet katkısından yararlanın',
        'icon': 'piggy-bank',
        'type': 'pension'
    },
    {
        'title': 'Mobil Bankacılık',
        'description': 'Mobil uygulamamızı indirin, bankacılık işlemlerinizi kolayca yapın',
        'icon': 'mobile-alt',
        'type': 'mobile'
    }
]

def generate_account_number():
    """Generate a unique 16-digit account number"""
    return ''.join(secrets.choice(string.digits) for _ in range(16))

@app.route('/register', methods=['GET', 'POST'])
@security_headers
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor.', 'danger')
            return redirect(url_for('register'))
        
        user = User(username=username)
        user.set_password(password)
        user.account_number = generate_account_number()
        user.is_new_user = True  # Yeni kullanıcı flag'i
        user.registration_date = datetime.utcnow()
        
        db.session.add(user)
        db.session.commit()
        
        # Yeni kullanıcı için karşılama mesajlarını kaydet
        for message in WELCOME_MESSAGES:
            notification = Notification(
                user_id=user.id,
                title=message['title'],
                message=message['message'],
                type=message['type'],
                is_read=False
            )
            db.session.add(notification)
        
        # Yeni kullanıcı için önerileri kaydet
        for rec in NEW_USER_RECOMMENDATIONS:
            recommendation = UserRecommendation(
                user_id=user.id,
                title=rec['title'],
                description=rec['description'],
                icon=rec['icon'],
                type=rec['type'],
                is_completed=False
            )
            db.session.add(recommendation)
        
        db.session.commit()
        
        flash('Kayıt başarılı! Giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/messages')
@login_required
def messages():
    """Mesajlar sayfası"""
    received_messages = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.timestamp.desc()).all()
    sent_messages = Message.query.filter_by(sender_id=current_user.id).order_by(Message.timestamp.desc()).all()
    users = User.query.all()
    return render_template('messages.html', 
                         received_messages=received_messages,
                         sent_messages=sent_messages,
                         users=users)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    """Yeni mesaj gönderme"""
    recipient_username = request.form.get('recipient')
    content = request.form.get('content')
    
    if not all([recipient_username, content]):
        flash('Alıcı ve mesaj içeriği gereklidir', 'error')
        return redirect(url_for('messages'))
    
    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        flash('Alıcı bulunamadı', 'error')
        return redirect(url_for('messages'))
    
    message = Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        content=content
    )
    
    db.session.add(message)
    db.session.commit()
    
    flash('Mesaj gönderildi', 'success')
    return redirect(url_for('messages'))

@app.route('/mark_message_read/<int:message_id>', methods=['POST'])
@login_required
def mark_message_read(message_id):
    """Mesajı okundu olarak işaretle"""
    message = Message.query.get_or_404(message_id)
    
    if message.recipient_id != current_user.id:
        flash('Bu mesajı işaretleme yetkiniz yok', 'error')
        return redirect(url_for('messages'))
    
    message.is_read = True
    db.session.commit()
    
    return redirect(url_for('messages'))

# Borsa, Döviz ve Altın işlemleri için sabit değerler
STOCK_PRICES = {
    'THYAO': {'price': 245.80, 'change': 2.5},
    'GARAN': {'price': 78.45, 'change': -1.2},
    'ASELS': {'price': 45.20, 'change': 3.1},
    'KCHOL': {'price': 180.30, 'change': 0.8},
    'EREGL': {'price': 35.60, 'change': -0.5}
}

EXCHANGE_RATES = {
    'USD': {'buy': 31.45, 'sell': 31.35},
    'EUR': {'buy': 34.20, 'sell': 34.10},
    'GBP': {'buy': 39.80, 'sell': 39.70}
}

GOLD_PRICES = {
    'gram': {'buy': 2145.00, 'sell': 2140.00},
    'ceyrek': {'buy': 3500.00, 'sell': 3490.00},
    'yarim': {'buy': 7000.00, 'sell': 6980.00},
    'tam': {'buy': 14000.00, 'sell': 13960.00}
}

CREDIT_RATES = {
    'ihtiyac': {'rate': 2.49, 'max_amount': 50000, 'max_term': 36},
    'konut': {'rate': 1.89, 'max_amount': 1000000, 'max_term': 120},
    'arac': {'rate': 1.99, 'max_amount': 300000, 'max_term': 48}
}

@app.route('/stock', methods=['GET', 'POST'])
@login_required
def stock():
    """Borsa işlemleri sayfası"""
    if request.method == 'POST':
        try:
            stock_code = request.form.get('stock_code')
            amount = float(request.form.get('amount', 0))
            action = request.form.get('action')  # 'buy' veya 'sell'
            
            if stock_code not in STOCK_PRICES:
                flash('Geçersiz hisse kodu', 'error')
                return redirect(url_for('stock'))
            
            if amount <= 0:
                flash('Geçersiz miktar', 'error')
                return redirect(url_for('stock'))
            
            total_cost = STOCK_PRICES[stock_code]['price'] * amount
            
            if action == 'buy':
                if current_user.balance < total_cost:
                    flash('Yetersiz bakiye', 'error')
                    return redirect(url_for('stock'))
                current_user.balance -= total_cost
            else:  # sell
                current_user.balance += total_cost
            
            # İşlem kaydı
            transaction = Transaction(
                user_id=current_user.id,
                amount=total_cost if action == 'buy' else -total_cost,
                description=f'Borsa İşlemi: {stock_code} {action.upper()} {amount} adet',
                transaction_type='stock'
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            flash(f'İşlem başarılı: {stock_code} {action.upper()} {amount} adet', 'success')
            return redirect(url_for('stock'))
            
        except Exception as e:
            flash(f'İşlem hatası: {str(e)}', 'error')
            return redirect(url_for('stock'))
    
    return render_template('stock.html', stocks=STOCK_PRICES)

@app.route('/exchange', methods=['GET', 'POST'])
@login_required
def exchange():
    """Döviz işlemleri sayfası"""
    if request.method == 'POST':
        try:
            currency = request.form.get('currency')
            amount = float(request.form.get('amount', 0))
            action = request.form.get('action')  # 'buy' veya 'sell'
            
            if currency not in EXCHANGE_RATES:
                flash('Geçersiz döviz kodu', 'error')
                return redirect(url_for('exchange'))
            
            if amount <= 0:
                flash('Geçersiz miktar', 'error')
                return redirect(url_for('exchange'))
            
            rate = EXCHANGE_RATES[currency]['buy'] if action == 'buy' else EXCHANGE_RATES[currency]['sell']
            total_cost = rate * amount
            
            if action == 'buy':
                if current_user.balance < total_cost:
                    flash('Yetersiz bakiye', 'error')
                    return redirect(url_for('exchange'))
                current_user.balance -= total_cost
            else:  # sell
                current_user.balance += total_cost
            
            # İşlem kaydı
            transaction = Transaction(
                user_id=current_user.id,
                amount=total_cost if action == 'buy' else -total_cost,
                description=f'Döviz İşlemi: {currency} {action.upper()} {amount}',
                transaction_type='exchange'
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            flash(f'İşlem başarılı: {currency} {action.upper()} {amount}', 'success')
            return redirect(url_for('exchange'))
            
        except Exception as e:
            flash(f'İşlem hatası: {str(e)}', 'error')
            return redirect(url_for('exchange'))
    
    return render_template('exchange.html', rates=EXCHANGE_RATES)

@app.route('/gold', methods=['GET', 'POST'])
@login_required
def gold():
    """Altın işlemleri sayfası"""
    if request.method == 'POST':
        try:
            gold_type = request.form.get('gold_type')
            amount = float(request.form.get('amount', 0))
            action = request.form.get('action')  # 'buy' veya 'sell'
            
            if gold_type not in GOLD_PRICES:
                flash('Geçersiz altın türü', 'error')
                return redirect(url_for('gold'))
            
            if amount <= 0:
                flash('Geçersiz miktar', 'error')
                return redirect(url_for('gold'))
            
            rate = GOLD_PRICES[gold_type]['buy'] if action == 'buy' else GOLD_PRICES[gold_type]['sell']
            total_cost = rate * amount
            
            if action == 'buy':
                if current_user.balance < total_cost:
                    flash('Yetersiz bakiye', 'error')
                    return redirect(url_for('gold'))
                current_user.balance -= total_cost
            else:  # sell
                current_user.balance += total_cost
            
            # İşlem kaydı
            transaction = Transaction(
                user_id=current_user.id,
                amount=total_cost if action == 'buy' else -total_cost,
                description=f'Altın İşlemi: {gold_type} {action.upper()} {amount}',
                transaction_type='gold'
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            flash(f'İşlem başarılı: {gold_type} {action.upper()} {amount}', 'success')
            return redirect(url_for('gold'))
            
        except Exception as e:
            flash(f'İşlem hatası: {str(e)}', 'error')
            return redirect(url_for('gold'))
    
    return render_template('gold.html', gold_rates=GOLD_PRICES)

@app.route('/credit', methods=['GET', 'POST'])
@login_required
def credit():
    """Kredi işlemleri sayfası"""
    if request.method == 'POST':
        try:
            credit_type = request.form.get('credit_type')
            amount = float(request.form.get('amount', 0))
            term = int(request.form.get('term', 0))
            
            if credit_type not in CREDIT_RATES:
                flash('Geçersiz kredi türü', 'error')
                return redirect(url_for('credit'))
            
            if amount <= 0 or amount > CREDIT_RATES[credit_type]['max_amount']:
                flash('Geçersiz kredi tutarı', 'error')
                return redirect(url_for('credit'))
            
            if term <= 0 or term > CREDIT_RATES[credit_type]['max_term']:
                flash('Geçersiz vade süresi', 'error')
                return redirect(url_for('credit'))
            
            # Aylık taksit hesaplama
            monthly_rate = CREDIT_RATES[credit_type]['rate'] / 100
            monthly_payment = (amount * monthly_rate * (1 + monthly_rate)**term) / ((1 + monthly_rate)**term - 1)
            total_payment = monthly_payment * term
            
            # Kredi işlemini gerçekleştir
            current_user.balance += amount
            
            # İşlem kaydı
            transaction = Transaction(
                user_id=current_user.id,
                amount=amount,
                description=f'Kredi Alındı: {credit_type} {amount} TL - {term} ay',
                transaction_type='credit'
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            flash(f'Kredi başarıyla alındı. Aylık taksit: {monthly_payment:.2f} TL', 'success')
            return redirect(url_for('credit'))
            
        except Exception as e:
            flash(f'İşlem hatası: {str(e)}', 'error')
            return redirect(url_for('credit'))
    
    return render_template('credit.html', rates=CREDIT_RATES)

@app.route('/credit_card', methods=['GET', 'POST'])
@login_required
def credit_card():
    """Kredi kartı işlemleri sayfası"""
    if request.method == 'POST':
        try:
            card_type = request.form.get('card_type')
            
            if card_type not in ['classic', 'gold', 'platinum']:
                flash('Geçersiz kart türü', 'error')
                return redirect(url_for('credit_card'))
            
            # Kart ücretleri
            card_fees = {
                'classic': 100,
                'gold': 250,
                'platinum': 500
            }
            
            if current_user.balance < card_fees[card_type]:
                flash('Yetersiz bakiye', 'error')
                return redirect(url_for('credit_card'))
            
            # Kart ücretini düş
            current_user.balance -= card_fees[card_type]
            
            # İşlem kaydı
            transaction = Transaction(
                user_id=current_user.id,
                amount=card_fees[card_type],
                description=f'Kredi Kartı Başvurusu: {card_type.upper()}',
                transaction_type='credit_card'
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            flash(f'Kredi kartı başvurunuz alındı: {card_type.upper()}', 'success')
            return redirect(url_for('credit_card'))
            
        except Exception as e:
            flash(f'İşlem hatası: {str(e)}', 'error')
            return redirect(url_for('credit_card'))
    
    return render_template('credit_card.html')

@app.route('/admin/fetch', methods=['GET', 'POST'])
@admin_required
@security_headers
def admin_fetch():
    """Admin bilgilerini getir - Güvenli versiyon (SSRF korumalı)"""
    # Sadece admin kullanıcılar erişebilir
    if not current_user.is_admin:
        return render_template('error.html', 
                            title='Erişim Reddedildi',
                            message='Bu sayfaya erişim yetkiniz yok'), 403
    
    result = None
    error = None
    
    if request.method == 'POST':
        try:
            encoded_url = request.form.get('url', '')
            if not encoded_url:
                error = 'URL gerekli'
                return render_template('admin_fetch.html', error=error)
            
            # Base64 decode
            try:
                decoded_url = base64.b64decode(encoded_url).decode('utf-8')
            except Exception as e:
                error = 'Geçersiz URL formatı'
                return render_template('admin_fetch.html', error=error)
            
            # URL güvenlik kontrolü
            try:
                parsed_url = urlparse(decoded_url)
                
                # Sadece HTTPS protokollerine izin ver
                if parsed_url.scheme not in ['https']:
                    error = 'Sadece HTTPS protokolleri desteklenir'
                    return render_template('admin_fetch.html', error=error)
                
                # İç IP adreslerini engelle
                hostname = parsed_url.hostname
                if not hostname:
                    error = 'Geçersiz hostname'
                    return render_template('admin_fetch.html', error=error)
                
                # Tehlikeli hostname'leri engelle
                dangerous_hosts = [
                    'localhost', '127.0.0.1', '::1', '0.0.0.0',
                    '169.254.169.254',  # AWS metadata
                    'metadata.google.internal',  # Google metadata
                    '169.254.169.254',  # Azure metadata
                ]
                
                if hostname in dangerous_hosts or \
                   hostname.startswith('192.168.') or \
                   hostname.startswith('10.') or \
                   hostname.startswith('172.') or \
                   hostname.startswith('169.254.'):
                    error = 'İç IP adreslerine erişim engellendi'
                    return render_template('admin_fetch.html', error=error)
                
                # Sadece güvenli domain'lere izin ver
                allowed_domains = [
                    'api.bank.com',
                    'secure.bank.com',
                    'internal.bank.com'
                ]
                
                if not any(hostname.endswith(domain) for domain in allowed_domains):
                    error = 'Sadece güvenli domain\'lere erişim izin verilir'
                    return render_template('admin_fetch.html', error=error)
                
                # URL'yi fetch et
                response = requests.get(decoded_url, timeout=5, verify=True)
                response.raise_for_status()
                
                # Maksimum boyut kontrolü (1MB)
                content_length = int(response.headers.get('content-length', 0))
                if content_length > 1024 * 1024:
                    error = 'Dosya boyutu çok büyük'
                    return render_template('admin_fetch.html', error=error)
                
                result = response.text
                
            except requests.exceptions.RequestException as e:
                error = f'URL erişim hatası: {str(e)}'
                return render_template('admin_fetch.html', error=error)
            
        except Exception as e:
            error = f'Beklenmeyen hata: {str(e)}'
            return render_template('admin_fetch.html', error=error)
    
    return render_template('admin_fetch.html', result=result, error=error)

@app.route('/konut-sigortasi')
@security_headers
def konut_sigortasi():
    """Konut sigortası sayfası"""
    return render_template('konut_sigortasi.html')

@app.route('/arac-sigortasi')
@security_headers
def arac_sigortasi():
    """Araç sigortası sayfası"""
    return render_template('arac_sigortasi.html')

@app.route('/saglik-sigortasi')
@security_headers
def saglik_sigortasi():
    """Sağlık sigortası sayfası"""
    return render_template('saglik_sigortasi.html')

@app.route('/seyahat-sigortasi')
@security_headers
def seyahat_sigortasi():
    """Seyahat sigortası sayfası"""
    return render_template('seyahat_sigortasi.html')

@app.route('/kart-islemleri')
@login_required
@security_headers
def kart_islemleri():
    """Kart işlemleri sayfası"""
    return render_template('kart_islemleri.html')

@app.route('/ozel-kampanyalar')
@login_required
@security_headers
def ozel_kampanyalar():
    """Size özel kampanyalar sayfası"""
    return render_template('ozel_kampanyalar.html')

if __name__ == '__main__':
    # Geliştirme sunucusu
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=False,
        ssl_context=None  # SSL'i devre dışı bırak
    )