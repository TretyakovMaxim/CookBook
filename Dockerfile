FROM python:slim

RUN useradd cookbook

WORKDIR /home/cookbook

COPY requirements.txt requirements.txt
RUN python -m venv venv
RUN venv/bin/pip install -r requirements.txt
RUN venv/bin/pip install gunicorn pymysql cryptography

COPY blog blog
COPY migrations migrations
COPY cookbook.py config.py boot.sh ./
RUN chmod a+x boot.sh

ENV FLASK_APP cookbook.py

RUN chown -R cookbook:cookbook ./
USER cookbook

EXPOSE 5000
ENTRYPOINT ["./boot.sh"]