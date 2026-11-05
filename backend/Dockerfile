FROM python:3.12.16-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/srv/backend PIP_NO_CACHE_DIR=1
WORKDIR /srv/backend
COPY backend/requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip setuptools wheel && pip install -r requirements.txt
COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini ./alembic.ini
EXPOSE 8000
USER 10001:10001
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
