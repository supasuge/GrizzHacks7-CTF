FROM ubuntu:22.04

# Install required packages
RUN apt-get update && \
    apt-get install -y socat binutils make gcc supervisor && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
ARG USER_UID=1000
ARG USER_GID=1000
ARG USERNAME=ctfuser
# Create a non-root user to run the challenge.
RUN groupadd --gid ${USER_GID} ${USERNAME} && \
    useradd --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME}

# Set working directory
WORKDIR /chal

# Copy the challenge binary, flag, and supervisor configuration.
COPY Makefile /chal/Makefile
COPY main.c /chal/main.c
COPY flag.txt /chal/flag.txt
COPY supervisord.conf /chal/supervisord.conf
RUN make
# Set files to read-only and change ownership to chaluser.

# Expose the port for the challenge (1337)
EXPOSE 1337
USER ctfuser
# Start supervisor (which will launch socat as chaluser)
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./chal,pty,raw,echo=0"]
