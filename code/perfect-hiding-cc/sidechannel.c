/*
 * SideChannel by Steffen Schulz © 2009
 * 
 * Hooks into Linux netfilter infrastructure and delays packets based
 * the number of µsecs supplied from stdin. If the last packet is longer
 * ago than intended delay, don't delay at all.
 * 
 * Compile with cc -o sidechannel -l netfilter_queue sidechannel.c
 * Use iptables -j QUEUE to pipe packets into this program.
 *
 */
 
#include "sidechannel.h"

#define DEBUG (0)

struct nfq_handle 	*nfqh;
struct nfq_q_handle *qh;
struct nfnl_handle  *nh;
u_int32_t id;  // reference to packet. if not using pkt header, simply increment
long delay;    // usec to delay each packet
struct timespec now;
struct timespec wait;
struct timespec last_time;
char line[50];
int cache = 0; // if delay<0, shall we wait a little to build up cache?
int counter = 0;
int period = 1; // only process every period'th packet
unsigned int processed = 0; // statistics
unsigned int imprinted = 0; // statistics
int real_delay = 0;
int nobuf = 0; // do not buffer (-> if pkt was buffered, drop it)


int main(int argc, char **argv) {

	int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
	period--; // counter starts at 0

	if (argc > 1)
		cache = 1;

	if(getuid() != 0) {
        fail("Only root can use me.");
    }

	/* make stdin non-blocking, i.e. optional */
	int flags = fcntl(0, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(0, F_SETFL, flags);


	/* close nfq hooks on exit */
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


    printf("exiting..\n");

    return 0;
}

int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
							struct nfq_data	*nfa, void *data) {


	clock_gettime(CLOCK_REALTIME, &now);

	int inherent= (1000*1000*(now.tv_sec - last_time.tv_sec) +
						(now.tv_nsec - last_time.tv_nsec)/1000);

	if (nobuf && (inherent < 30)) { // packet comes from cache
		nfq_set_verdict(qh, id++, NF_DROP, 0, NULL);
		return OK;
	}

	/* read() inter-packet delay from stdin, sleep(), then accept() */

	if (counter == period) {
		counter = 0;
		if (fgets(line, 49, stdin))
			delay = atol(line);
		else
		delay = 0;
	} else {
		counter++; // only process every period'th packet
		delay = 0;
	}
    
	/* use pkd id from header or just count up? 
	 *   - we must not re-order packets
	 *   - we must be fast, i.e. if possible don't copy packet contents
     * struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
     * u_int32_t id = ntohl(ph->packet_id);
	 */
     // struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
     // u_int32_t id = ntohl(ph->packet_id);

	
    real_delay = delay - inherent;
	//1000*1000*(now.tv_sec-last_time.tv_sec) + (now.tv_nsec - last_time.tv_nsec)/1000;


    if DEBUG {
        printf("Run %d\n",id);
        printf("\t  inherent delay: %dµs\n", inherent);
        printf("\t  intended delay: %dµs\n", delay);
        printf("\t remaining delay: %dµs\n", real_delay);
    }
    
	if (real_delay > 0) {
		usleep(real_delay);
        imprinted++;
		if DEBUG
            printf("\tdelay: %d µs\n",real_delay);
	} else {
		if DEBUG
			if (cache) {
            	printf("\tdelay was negative..forcing cache buildup\n");
				usleep(100000);
			} else {
            	printf("\tdelay was negative..\n");
			}
			
	}
    processed++;

	clock_gettime(CLOCK_REALTIME, &now);
	last_time.tv_sec = now.tv_sec;
	last_time.tv_nsec = now.tv_nsec;
    
	nfq_set_verdict(qh, id++, NF_ACCEPT, 0, NULL);

	return OK;
}

/* Basic signal handler closes nfq hooks on exit */
static void sig_handler(int signum) {
	
	printf("\nCaught Signal ...\n\n");

    printf("Stats: %d out of %d(%d) processed successfully\n",imprinted, processed, processed/(period+1));

	nfq_destroy_queue(qh);
	nfq_close(nfqh);
	exit(OK);
}

static int fail(char *str) {

	fprintf(stderr, "%s\n", str);
	exit(ERROR);
}
