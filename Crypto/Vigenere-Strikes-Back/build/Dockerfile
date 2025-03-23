FROM python:3.12-slim
WORKDIR /app
COPY chal.py message.txt ./
RUN chmod +x chal.py && \
    apt-get update && \
    apt-get install -y socat supervisor && \
    rm -rf /var/lib/apt/lists/*
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
EXPOSE 7474
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]