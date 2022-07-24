FROM python:latest

ARG DEBIAN_FRONTEND="noninteractive"
ENV TZ=Australia/Sydney

RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y supervisor

COPY requirements.txt /srv
WORKDIR /srv
RUN pip install -r requirements.txt

COPY . /srv

EXPOSE 5000/tcp

CMD ["supervisord","-c","/srv/supervisor.conf"]
