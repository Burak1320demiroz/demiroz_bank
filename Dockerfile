# Temel imaj (Python 3.9 kullanılıyor)
FROM python:3.9-slim

# Ortam değişkenleri
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Gerekli sistem paketlerini kur (örneğin PostgreSQL geliştime başlıkları vb.)
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    gcc \
    netcat-openbsd \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Çalışma dizinini ayarla
WORKDIR /app

# Proje dosyalarını konteynere kopyala
COPY . /app

# Python paket yöneticisini güncelle ve bağımlılıkları yükle
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Uygulamanın dinleyeceği port
EXPOSE 5000

# Uygulama başlatma komutu
CMD ["python", "app.py"]
