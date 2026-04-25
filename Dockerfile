# Stage 1: Build React frontend
FROM node:20-slim AS frontend
WORKDIR /frontend
COPY frontend/package*.json .
RUN npm ci
COPY frontend/ .
RUN npm run build

# Stage 2: Python backend + built frontend
FROM python:3.12-slim
WORKDIR /app

# Install Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ app/
COPY migrations/ migrations/

# Copy built frontend from Stage 1
COPY --from=frontend /frontend/dist frontend/dist

# Data volume for SQLite persistence
VOLUME /data
ENV DATABASE_PATH=/data/vulnapps.db

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
