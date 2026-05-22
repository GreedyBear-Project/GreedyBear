## ------------------------------- UV Stage ------------------------------ ## 

FROM python:3.13-slim-trixie AS uv

COPY --from=ghcr.io/astral-sh/uv:0.11.1 /uv /bin/uv
COPY pyproject.toml .  

RUN echo "VITE_GREEDYBEAR_VERSION=\"$(uv version --short)\"" > .env.local


## ------------------------------- Frontend Build Stage ------------------------------ ## 

FROM node:lts-alpine3.22 AS frontend-build

WORKDIR /app

# install dependencies first for layer caching
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# copy source code and build
COPY frontend/ .
COPY --from=uv /.env.local .
RUN VITE_BASE_URL=/static/reactapp/ npm run build


## ------------------------------- Production Stage ------------------------------ ##

FROM uv AS production

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=greedybear.settings
ENV APP_ROOT=/opt/deploy/greedybear
ENV LOG_PATH=/var/log/greedybear
ENV UV_PROJECT_ENVIRONMENT=/usr/local

WORKDIR $APP_ROOT

# Layer 1: stable runtime OS deps — cached across pyproject.toml/uv.lock changes.
#  libgomp1: model training; curl: healthcheck; gosu: entrypoint privilege drop
#  libpq5: runtime shared library required by the psycopg[c] C extension
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 curl gosu libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Layer 2: Python packages — only re-runs when pyproject.toml/uv.lock change.
#  Build-only deps (gcc, python3-dev, libpq-dev) compile the psycopg[c] C
#  extension and are purged in the same layer to keep the final image lean.
COPY pyproject.toml uv.lock ./
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc python3-dev libpq-dev \
    && uv sync --no-dev --locked \
    && uv cache clean \
    && apt-get purge -y gcc python3-dev libpq-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy files
COPY . $APP_ROOT
COPY --from=frontend-build /app/build /var/www/reactapp

# Set up log directories, fix permissions, and remove frontend source (served from /var/www/reactapp)
RUN mkdir -p ${LOG_PATH}/django ${LOG_PATH}/gunicorn \
    && touch ${LOG_PATH}/django/api.log ${LOG_PATH}/django/api_errors.log \
    && touch ${LOG_PATH}/django/greedybear.log ${LOG_PATH}/django/greedybear_errors.log \
    && touch ${LOG_PATH}/django/django_q.log ${LOG_PATH}/django/django_q_errors.log \
    && touch ${LOG_PATH}/django/django_errors.log ${LOG_PATH}/django/elasticsearch.log \
    && touch ${LOG_PATH}/django/authentication.log ${LOG_PATH}/django/authentication_errors.log \
    && mkdir -p ${APP_ROOT}/mlmodels \
    && chown -R www-data:www-data ${LOG_PATH} /opt/deploy/ ${APP_ROOT}/mlmodels/ \
    && rm -rf frontend/


## ------------------------------- Development Stage ------------------------------ ##

FROM production AS development

# Install dev + test dependencies (hot-reload tools + test runners)
RUN uv sync --group dev --group test --locked


## ------------------------------- Default Stage ------------------------------ ##

# Ensure the default build target is production
FROM production
