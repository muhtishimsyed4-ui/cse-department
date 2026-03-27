# ──────────────────────────────────────────────
#  NetGuard — Dockerfile
#  Base: Debian slim (same OS as Kali, no changes needed)
# ──────────────────────────────────────────────
FROM python:3.11-slim

# Install system tools required by the app
RUN apt-get update && apt-get install -y --no-install-recommends \
        arp-scan \
        nmap \
        sudo \
        net-tools \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Working directory inside container
WORKDIR /app

# Install Python dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all application source files
COPY app.py config.py database.py scanner.py \
     security_scanner.py email_notifier.py schema.sql ./
COPY templates/ templates/
COPY static/ static/

# Persistent data directory (SQLite DB goes here via volume mount)
RUN mkdir -p /data

# Expose the dashboard port
EXPOSE 5000

# Run as root — required for raw packet access (arp-scan, nmap)
# 'sudo' calls in the code still work when already root
CMD ["python", "app.py"]
