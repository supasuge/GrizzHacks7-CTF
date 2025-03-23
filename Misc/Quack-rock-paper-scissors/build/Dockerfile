FROM python:3.12-slim

WORKDIR /app

COPY chall.py flag.txt /app/

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    socat \
    supervisor && \
    rm -rf /var/lib/apt/lists/*

COPY supervisord.conf /etc/supervisor/supervisord.conf

RUN chmod +x /app/chall.py  && chmod 644 /app/flag.txt

EXPOSE 8844

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
