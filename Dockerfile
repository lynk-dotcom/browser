FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Install Chromium, Xvfb, and required system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        chromium \
        chromium-common \
        xvfb \
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
    DISPLAY=:99 \
    CDP_HEADLESS=0 \
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

# Start Xvfb, configure the display, and launch the application
ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["sh", "-c", "Xvfb :99 -screen 0 1920x1080x24 -ac & while ! xdpyinfo -display :99 >/dev/null 2>&1; do sleep 0.2; done; export DISPLAY=:99; export CDP_HEADLESS=0; exec python3 brow.py"]