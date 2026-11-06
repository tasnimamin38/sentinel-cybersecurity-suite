FROM python:3.13.18-slim-trixie AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/srv/backend \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/backend

COPY backend/requirements.txt ./requirements.txt

RUN python -m pip install --upgrade pip "setuptools>=78.1.1" wheel \
    && pip install -r requirements.txt \
    && python -c 'import setuptools; v=tuple(int(x) for x in setuptools.__version__.split(".")[:3]); assert v >= (78, 1, 1), setuptools.__version__'

COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini ./alembic.ini

FROM debian:trixie-slim AS runtime

ENV PATH=/usr/local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/srv/backend \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/backend

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        python3.13 \
        ca-certificates \
        netbase \
        tzdata \
        passwd \
    ; \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 sentinel \
    && useradd --system --uid 10001 --gid sentinel --home-dir /nonexistent --shell /usr/sbin/nologin sentinel

COPY --from=builder /usr/local /usr/local
COPY --from=builder --chown=10001:10001 /srv/backend /srv/backend

RUN python -c 'import fastapi, uvicorn, sqlalchemy, psycopg, cryptography, dns; print("Python runtime OK")'

USER 10001:10001

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
