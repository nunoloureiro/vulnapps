#!/bin/bash
set -euo pipefail

# ============================================================
# Vulnapps - EC2 Setup Script
# Run this on a fresh Amazon Linux 2023 / Ubuntu EC2 instance.
# Assumes Docker is already installed (use TaintedPort setup or install manually).
# ============================================================

echo "============================================"
echo "  Vulnapps - EC2 Setup"
echo "============================================"

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
sudo docker volume create vulnapps-data 2>/dev/null || true

# --- Start the container ---
echo "[4/4] Starting Vulnapps..."
sudo docker stop vulnapps 2>/dev/null || true
sudo docker rm vulnapps 2>/dev/null || true
sudo docker run -d \
    --name vulnapps \
    --restart unless-stopped \
    -p 127.0.0.1:8001:8000 \
    -v vulnapps-data:/data \
    -e SECRET_KEY="${SECRET_KEY:-$(openssl rand -hex 32)}" \
    -e DATABASE_PATH=/data/vulnapps.db \
    -e TOKEN_EXPIRY_HOURS=24 \
    vulnapps:latest

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
