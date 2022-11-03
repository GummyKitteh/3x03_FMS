FROM python:3.9-slim-buster

WORKDIR usr/src/flaskapp
RUN mkdir logs
COPY . .
RUN apt update && apt install libmariadb-dev build-essential -y
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt
