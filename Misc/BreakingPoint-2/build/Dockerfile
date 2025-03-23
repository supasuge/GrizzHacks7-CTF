FROM python:3.12-slim

ENV LANG C.UTF-8
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app
RUN apt-get update -y && \
    apt-get upgrade -y && \ 
    apt-get install socat supervisor -y --no-install-recommends 

COPY jail.py /app/jail.py
COPY flag.txt /app/flag.txt
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]