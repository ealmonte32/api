FROM python:3.7-slim-stretch
WORKDIR /usr/src/app

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev libltdl-dev && \
    apt-get clean

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

CMD FLASK_APP=server.py flask run
