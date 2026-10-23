FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Install Chromium and required system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        chromium \
        chromium-common \
        fonts-liberation \
        ca-certificates \
        tini \
        libnss3 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libcups2 \
        libdrm2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libpango-1.0-0 \
        libcairo2 \
        libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Verify Chromium is installed and executable
RUN test -x /usr/bin/chromium \
    && /usr/bin/chromium --version

# Application configuration
ENV HOME=/tmp \
    CDP_HEADLESS=1 \
    CHROME_BIN=/usr/bin/chromium \
    PORT=8080 \
    DEFAULT_SEARCH_ENGINE=ddg \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create a non-root user and prepare browser directories
RUN useradd -u 10001 -M -s /usr/sbin/nologin lynk \
    && mkdir -p /app/.lynkio-chrome /tmp/.lynkio-chrome \
    && chown -R lynk:lynk /app /tmp/.lynkio-chrome

# Run as a non-root user
USER lynk

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "brow.py"]