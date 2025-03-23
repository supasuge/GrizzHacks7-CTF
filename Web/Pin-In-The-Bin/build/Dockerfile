FROM python:3.12-slim
ENV PATH="/usr/local/bin:${PATH}"
RUN useradd -m -s /bin/bash ctf
RUN usermod -aG sudo ctf
RUN mkdir -p /home/ctf/app
WORKDIR /home/ctf/app
RUN ln -s /usr/local/bin/python3 /usr/bin/python3
COPY flag.txt /home/ctf/app/
COPY requirements.txt /home/ctf/app/
COPY app.py /home/ctf/app/
COPY forms.py /home/ctf/app/
COPY utils.py /home/ctf/app/
COPY supervisord.conf /home/ctf/app/
COPY templates/ /home/ctf/app/templates/
COPY static/ /home/ctf/app/static/
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y gunicorn supervisor --no-install-recommends && \
    pip install -r requirements.txt --no-cache-dir && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    touch /var/log/app.err.log /var/log/app.out.log && \
    chmod -R 755 /var/log && \
    chown -R ctf:ctf /home/ctf/ && \
    chown -R ctf:ctf /var/log && \
    chown -R ctf:ctf /usr/bin/supervisord && \
    chown -R ctf:ctf /usr/bin/gunicorn && \
    chown -R ctf:ctf /usr/bin/python3

EXPOSE 5000
USER ctf
CMD ["supervisord", "-c", "/home/ctf/app/supervisord.conf"]
