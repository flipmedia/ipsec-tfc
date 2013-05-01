all: token-secure

clean:
	rm -f token-secure

token-secure: token-secure.c tradeoff.h config.h
	cc -o token-secure -lm -lpcap -lpthread token-secure.c
