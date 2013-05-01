/*
 * PktGen by Steffen Schulz © 2009
 *
 * Braindead TCP server that waits for a packet and then
 * - replies with stream of packets
 * - with inter-packet delays read as integers from stdin
 *
 * Disables Nagle Algo to prevent buffering in local network stack
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#define DEBUG (1)


/* Basic signal handler closes nfq hooks on exit */
static void sig_handler(int signum) {

	printf("\nCaught Signal ...\n\n");
	exit(0);
}

int main(int argc, char **argv) {

	struct sockaddr_in sin;
	struct sockaddr_in sout;
	int s = socket(AF_INET,SOCK_STREAM,0);
	unsigned int slen = sizeof(sout);
	unsigned int len = 0;
	char line[500];
	long delay = 0;
	unsigned int cntr = 0;
	int port = 1194;
    int tmp = 0;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = INADDR_ANY;

	/* make stdin non-blocking, i.e. optional */
	int flags = fcntl(0, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(0, F_SETFL, flags);

	/* close nfq hooks on exit */
	if (signal(SIGINT, sig_handler) == SIG_IGN)
		signal(SIGINT, SIG_IGN);
	if (signal(SIGHUP, sig_handler) == SIG_IGN)
		signal(SIGHUP, SIG_IGN);
	if (signal(SIGTERM, sig_handler) == SIG_IGN)
		signal(SIGTERM, SIG_IGN);

	// wait for conn, store peer in sout

	bind(s, (struct sockaddr *)&sin, sizeof(sin));
	listen(s, 2);

	int c = accept(s, (struct sockaddr *)&sout, &tmp);
	tmp=1;
	if (setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &tmp, sizeof(tmp)) < 0)
			fprintf(stderr, "Error when disabling buffer..\n");

	printf("Got connection from %s:%d, start sending..\n",
			inet_ntoa(sout.sin_addr), ntohs(sout.sin_port));

	len = snprintf(line, 499, "%010d\n",cntr++);

	send(c, line, len+1,0);

	while (1) {

		if (fgets(line, 49, stdin)) {
			delay = atol(line);
		}
		else {
			if (argc > 1)
				exit(0);
			delay = 5000;
		}

		if (delay < 0)
			delay = 0;

	usleep(delay);
	len = snprintf(line, 499, "%010d\n",cntr++);
	send(c, line, len+1,0);
	}
}
