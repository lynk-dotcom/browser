FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        chromium-common \
        fonts-liberation \
        ca-certificates \
        tini \
        libnss3 libatk-bridge2.0-0 libatk1.0-0 libcups2 libdrm2 \
        libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
        libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Sanity check: fail the build if chromium is a snap shim or broken
RUN file /usr/bin/chromium | grep -q ELF \
    && /usr/bin/chromium --version

ENV HOME=/tmp \
    CDP_HEADLESS=1 \
    CHROME_BIN=/usr/bin/chromium \
    PORT=8080 \
    DEFAULT_SEARCH_ENGINE=ddg \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

RUN useradd -u 10001 -M -s /sbin/nologin lynk \
    && mkdir -p /app/.lynkio-chrome /tmp/.lynkio-chrome \
    && chown -R lynk:lynk /app /tmp

USER lynk
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "brow.py"]