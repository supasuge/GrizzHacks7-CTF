FROM ubuntu:latest

# Install required packages: gcc, make, socat, and supervisor.
RUN apt-get update -y && apt-get upgrade -y && apt-get autoremove && \
    apt-get install -y gcc make socat supervisor && \
    rm -rf /var/lib/apt/lists/*

# Create challenge directory and copy files.
WORKDIR /challenge
COPY chal.c .
COPY Makefile .
COPY flag.txt .
COPY supervisord.conf /etc/supervisor/conf.d/chal.conf

# Build the challenge.
RUN make

# Expose TCP port 1337.
EXPOSE 9004

# Start Supervisor to launch socat, which will spawn the chal binary.
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/chal.conf"]

