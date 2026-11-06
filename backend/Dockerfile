FROM python:3.12.16-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/srv/backend PIP_NO_CACHE_DIR=1
WORKDIR /srv/backend
COPY backend/requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip "setuptools>=78.1.1" wheel \
    && pip install -r requirements.txt \
    && python -c 'import setuptools; v=tuple(int(x) for x in setuptools.__version__.split(".")[:3]); assert v >= (78, 1, 1), setuptools.__version__' \
    && bundle_dir="$(python -c 'import ensurepip; from pathlib import Path; print(Path(ensurepip.__file__).parent / "_bundled")')" \
    && find "$bundle_dir" -maxdepth 1 -type f -name 'setuptools-*.whl' -print -delete \
    && test -z "$(find "$bundle_dir" -maxdepth 1 -type f -name 'setuptools-*.whl' -print -quit)"
COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini ./alembic.ini
EXPOSE 8000
USER 10001:10001
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
