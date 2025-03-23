CC=gcc
CFLAGS= -fno-stack-protector -no-pie -O0
all: chal

chal: chal.c
	$(CC) $(CFLAGS) -o chal chal.c

clean:
	rm -f chal

