FROM python:3.12-slim

RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends socat supervisor && \
    rm -rf /var/lib/apt/lists/* 
    


RUN useradd -m -s /bin/bash ctf

WORKDIR /home/ctf

COPY jail.py .
COPY flag.txt .
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN chmod 555 /home/ctf/jail.py && \
    chmod 444 /home/ctf/flag.txt && \
    chmod 777 /etc/supervisor/conf.d/supervisord.conf && \
    chmod 777 /usr/bin/supervisord

USER ctf
EXPOSE 8888
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
