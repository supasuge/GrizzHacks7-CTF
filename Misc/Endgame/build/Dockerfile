FROM python:3.12-slim

RUN apt-get update -y && apt-get install -y socat supervisor && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip3 install numpy
COPY chal.py /app/chal.py
COPY flag.txt /app/flag.txt
COPY supervisord.conf /app/supervisord.conf
RUN chmod +x /app/chal.py
EXPOSE 7777
CMD ["/usr/bin/supervisord", "-c", "/app/supervisord.conf"]
