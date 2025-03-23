FROM ubuntu:22.04

RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y socat binutils make gcc 

WORKDIR /challenge
COPY flag.txt .
COPY vuln.c .
COPY Makefile .

RUN make
RUN rm -f vuln.c Makefile
EXPOSE 13372
CMD ["socat", "TCP-LISTEN:13372,reuseaddr,fork", "EXEC:./vuln"]
