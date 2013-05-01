/*
 * IPDinject
 * Copyright (c) 2010-2012 Steffen Schulz
 * 
 * Hooks into Linux netfilter queue and delays the forwarding of packets based
 * on input from <stdin>. Requires some 'iptables -j QUEUE' rule in the
 * FORWARDING chain that can also select the IP streams to manipulate.
 * 
 * Compiled as cc -o ipd -l netfilter_queue -l rt ipd.c
 *
 * Input from <stdin> should be one integer per line, specifying an intended IPD
 * in microseconds.
 *
 */
 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define OK 1
#define FALSE 0
#define ERROR -1

/*
 * Note: printf() is expensive and might influence timing/performance.
 * But if set to 0, the compiler will optimize this stuff away.
 */
#define DEBUG 0

struct nfq_handle 	*nfqh;
struct nfq_q_handle *qh;
struct nfnl_handle  *nh;
u_int32_t id;  	// reference to packet. if not using pkt header, simply increment
struct timespec now;
struct timespec wait;
struct timespec last_time;
char 	line[50];
unsigned long 	delay;    	// usec to delay each packet
unsigned int size; // size of packet, unsupported, only for compatible stdin interface
int 	real_delay = 0;
unsigned int processed = 0; // statistics
unsigned int imprinted = 0; // statistics


/* Basic signal handler: closes nfq hooks on exit */
static void sig_handler(int signum) {
	
	printf("\nIPD caught signal ...\n\n");

	nfq_destroy_queue(qh);
	nfq_close(nfqh);
	exit(OK);

}

/* Wrapper function to print error and exit */
static void fail(char *str) {

	fprintf(stderr, "%s\n", str);
	exit(ERROR);
}

/* Wait for packet. Delay action(accept/reject/drop) on packet until intended
 * inter-packet delay is reached. Then accept packet.
 * If intended delay is too low, then do not wait at all.
 */
int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
							struct nfq_data	*nfa, void *data) {

	clock_gettime(CLOCK_MONOTONIC, &now);

	int inherent = (1000*1000*(now.tv_sec - last_time.tv_sec) +
						(now.tv_nsec - last_time.tv_nsec)/1000);

	if (2 != fscanf(stdin,"%u %u\n",&delay, &size))
		delay = 20000; /* 20ms */

	real_delay = delay - inherent;

	if (DEBUG) {
		printf("Run %d\n",id);
		printf("\t  inherent delay: %dµs\n", inherent);
		printf("\t  intended delay: %dµs\n", delay);
		printf("\t remaining delay: %dµs\n", real_delay);
	}

	if (real_delay > 0) {
		usleep(real_delay);
        imprinted++;
		if (DEBUG)
			printf("\tdelay: %d µs\n",real_delay);
	} else {
		if (DEBUG) printf("\tdelay was negative..\n");
	}
	processed++;

	clock_gettime(CLOCK_REALTIME, &now);
	last_time.tv_sec = now.tv_sec;
	last_time.tv_nsec = now.tv_nsec;

	nfq_set_verdict(qh, id++, NF_ACCEPT, 0, NULL);

	return OK;
}

/*
 * Initialize stdin and nfq hook, then loop forever. Callback() does all the real work.
 */
int main(int argc, char **argv) {

	int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

	if(getuid() != 0) {
        fail("Only root can use me.");
    }

	/* make stdin non-blocking, i.e. optional */
	int flags = fcntl(0, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(0, F_SETFL, flags);


	/* signal handler will close nfq hooks on exit */
	if(signal(SIGINT, sig_handler) == SIG_IGN)
        signal(SIGINT, SIG_IGN);
    if(signal(SIGHUP, sig_handler) == SIG_IGN)
        signal(SIGINT, SIG_IGN);
    if(signal(SIGTERM, sig_handler) == SIG_IGN)
        signal(SIGINT, SIG_IGN);

	/* hook callback() into userspace netlink queue */
	if (!(nfqh = nfq_open()))
		fail("nfq_open() failed");

	if (0 > nfq_unbind_pf(nfqh, AF_INET))
		fail("nfq_unbind_pf failed");

	if (0 > nfq_bind_pf(nfqh, AF_INET))
		fail("nfq_bind_pf failed");

	if (!(qh = nfq_create_queue(nfqh, 0, &callback, NULL)))
		fail("nfq_create_queue failed");

	if (0 > nfq_set_mode(qh, NFQNL_COPY_META, 0xffff))
		fail("nfq_set_mode failed");

	nh = nfq_nfnlh(nfqh);
	fd = nfnl_fd(nh);


	printf("Commencing packet mangling..\n");

	clock_gettime(CLOCK_REALTIME, &last_time);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
		nfq_handle_packet(nfqh, buf, rv);


    printf("Exiting..\n");
    return 0;
}

