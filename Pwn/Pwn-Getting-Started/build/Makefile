CC=gcc
CFLAGS=-fno-stack-protector -no-pie -z execstack

all: vuln

vuln: vuln.c
	$(CC) $(CFLAGS) -o vuln vuln.c

clean: rm -f vuln.c