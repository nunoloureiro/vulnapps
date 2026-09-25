# Stage 1: Build React frontend
# Built natively on the build host's arch — output is static assets, so it
# doesn't need to match the target --platform, and running Node/esbuild
# under QEMU emulation is unstable (crashes the Go runtime in esbuild).
FROM --platform=$BUILDPLATFORM node:20-slim AS frontend
WORKDIR /frontend
COPY frontend/package*.json .
RUN npm ci
COPY frontend/ .
RUN npm test && npm run build

# Stage 2: Python backend + built frontend
FROM python:3.12-slim
WORKDIR /app

# Install Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ app/
COPY migrations/ migrations/
COPY VERSION .

# Commit count to main, computed on the build host (by build.sh) and passed
# in here since .git is excluded from the build context (see .dockerignore)
# and so isn't available to compute this from at runtime. See app/version.py.
ARG COMMIT_COUNT=0
RUN echo "$COMMIT_COUNT" > COMMIT_COUNT

# Release history, generated on the build host for the same reason (no .git in
# here to derive it from). Optional: the bracket makes the pattern match zero
# files without failing the build, and app/changelog.py then falls back to git
# — which finds nothing in the image, so the page simply reports it is
# unavailable rather than the whole build breaking. build.sh and the deploy
# workflow always generate it. See tools/gen_changelog.py.
COPY CHANGELOG.jso[n] ./

# Copy built frontend from Stage 1
COPY --from=frontend /frontend/dist frontend/dist

# Data volume for SQLite persistence
VOLUME /data
ENV DATABASE_PATH=/data/vulnapps.db

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
