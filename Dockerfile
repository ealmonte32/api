FROM python:3.7-slim-stretch
WORKDIR /usr/src/app

ENV PYTHONUNBUFFERED 1

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev libltdl-dev && \
    apt-get clean

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./

ENV CFSSL_SERVER wott-ca
ENV DJANGO_SETTINGS_MODULE backend.settings.prod

USER nobody
CMD gunicorn \
    --workers 4 \
    --access-logfile '-' \
    --bind 0.0.0.0:8000 \
    backend.wsgi
