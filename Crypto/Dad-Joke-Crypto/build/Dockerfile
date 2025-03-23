FROM python:3.12-slim
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY requirements.txt .
COPY app.py /app/
COPY utils.py /app/
COPY templates/ /app/templates/
COPY static/ /app/static/
COPY flag.txt /app/
COPY supervisord.conf /app/supervisord.conf

RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y gunicorn && \
    apt-get install -y supervisor --no-install-recommends -y && \
    pip install -r requirements.txt --no-cache-dir && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN touch /var/log/app.err.log /var/log/app.out.log && \
    chmod -R 755 /var/log

EXPOSE 6969

CMD ["supervisord", "-c", "/app/supervisord.conf"]