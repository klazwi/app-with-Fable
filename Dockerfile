# Słowo na dziś: the app and its server in one small image. Needs nothing beyond the Python standard library.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    SLOWO_DB=/data/slowo.db

# The server runs as an unprivileged user. It can write only to /data, where the database lives.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin slowo \
    && mkdir /data \
    && chown slowo:slowo /data

WORKDIR /app
COPY server.py index.html ./
COPY data ./data
COPY vendor ./vendor

USER slowo
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/me', timeout=4).status == 200 else 1)"]

CMD ["python", "server.py"]
