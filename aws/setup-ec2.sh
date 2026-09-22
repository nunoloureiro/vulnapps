#!/bin/bash
set -euo pipefail

# ============================================================
# Vulnapps - EC2 Setup Script
# Set up or update an Amazon Linux 2023 / Ubuntu EC2 instance.
# Usage: VULNAPPS_IMAGE=image bash aws/setup-ec2.sh [ENV_FILE]
# ============================================================

echo "============================================"
echo "  Vulnapps - EC2 Setup"
echo "============================================"

if [[ $# -gt 0 ]]; then
    grep -qE '^SECRET_KEY=.+$' "$1" || {
        echo 'The application env file must contain SECRET_KEY.' >&2
        exit 1
    }
    APP_ENV=(--env-file "$1")
else
    APP_ENV=(-e "SECRET_KEY=${SECRET_KEY:-$(openssl rand -hex 32)}" -e TOKEN_EXPIRY_HOURS=24)
fi

# --- Install Docker if needed ---
if ! command -v docker &> /dev/null; then
    echo "[1/4] Installing Docker..."
    if [ -f /etc/os-release ] && grep -q "amzn" /etc/os-release; then
        sudo yum update -y
        sudo yum install -y docker
        sudo systemctl enable docker
        sudo systemctl start docker
        sudo usermod -aG docker ec2-user
    else
        sudo apt-get update
        sudo apt-get install -y docker.io
        sudo systemctl enable docker
        sudo systemctl start docker
        sudo usermod -aG docker ubuntu
    fi
else
    echo "[1/4] Docker already installed."
fi

# --- Pull the image ---
DOCKER_IMAGE="${VULNAPPS_IMAGE:-nunoloureiro/vulnapps:latest}"
echo "[2/4] Pulling Vulnapps image: $DOCKER_IMAGE"
sudo docker pull "$DOCKER_IMAGE"
sudo docker tag "$DOCKER_IMAGE" vulnapps:latest

# --- Create data volume if it doesn't exist ---
echo "[3/4] Ensuring data volume exists..."
sudo docker volume create vulnapps-data >/dev/null

# --- Start the container ---
echo "[4/4] Starting Vulnapps..."
if sudo docker container inspect vulnapps >/dev/null 2>&1; then
    # SQLite's backup API includes committed WAL data while the old app is running.
    sudo docker run --rm -i --entrypoint python \
        -v vulnapps-data:/data "$DOCKER_IMAGE" - <<'PY'
import datetime
import pathlib
import sqlite3

directory = pathlib.Path('/data/deploy-backups')
directory.mkdir(exist_ok=True)
snapshot = directory / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.db')
with sqlite3.connect('file:/data/vulnapps.db?mode=ro', uri=True) as source:
    with sqlite3.connect(snapshot) as destination:
        source.backup(destination)
print(f'Database snapshot: {snapshot}')
PY
    sudo docker stop --time 30 vulnapps >/dev/null
    sudo docker rm vulnapps >/dev/null
fi
sudo docker run -d \
    --name vulnapps \
    --restart unless-stopped \
    -p 127.0.0.1:8001:8000 \
    -v vulnapps-data:/data \
    "${APP_ENV[@]}" \
    -e DATABASE_PATH=/data/vulnapps.db \
    -e STATE_DIR=/data/scan-state \
    "$DOCKER_IMAGE"

ready=false
for attempt in {1..30}; do
    if sudo docker exec vulnapps python -c \
        'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/api", timeout=2)' \
        >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 2
done
if [[ "$ready" != true ]]; then
    echo 'Startup check failed. Inspect docker logs on the host; any pre-deploy database snapshot is in /data/deploy-backups.' >&2
    exit 1
fi

if ! sudo docker image prune -f; then
    echo 'Warning: deployment succeeded, but dangling image cleanup failed.' >&2
fi

echo ""
echo "============================================"
echo "  Vulnapps is running!"
echo "  Container: 127.0.0.1:8001"
echo "  Data volume: vulnapps-data (persistent)"
echo "============================================"
echo ""
echo "Useful commands:"
echo "  docker logs vulnapps           # View logs"
echo "  docker restart vulnapps        # Restart"
echo "  docker stop vulnapps           # Stop"
echo "  docker start vulnapps          # Start again"
echo "  docker volume inspect vulnapps-data  # Check data volume"
