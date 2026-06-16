# NETH - container for the web app + Telegram bot.
FROM python:3.12-slim

# System libs: zbar (pyzbar QR decode) + glib (opencv-headless runtime).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libzbar0 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Fetch WeChat QR models so logo/stylized QR (e.g. ABA Pay) decode in prod.
RUN python scripts/fetch_wechat_models.py || echo "[build] wechat models skipped"

ENV PORT=8080
EXPOSE 8080
RUN chmod +x start.sh
CMD ["./start.sh"]
