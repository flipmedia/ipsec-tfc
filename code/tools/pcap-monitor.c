/*
 * Capture packets matching argv[2] from device argv[1]. Uses libpcap.
 * Copyright (c) 2010-2012 Steffen Schulz
 *
 * Prints *delay* between subsequent packets and several other relevant header fields.
 * Or, if called as 'bw-mon', prints overall throughput of the matching packet streams.
 *
 * Much of it is borrowed from http://www.tcpdump.org/pcap.htm
 *
 * Usage:
 * 
 * 		cc -o cc-mon -lpcap pcap-monitor.c
 * 		./cc-mon eth0 'ip src 10.0.0.1 and esp'
 * 		
 * 		cc -o bw-mon -lpcap pcap-monitor.c
 * 		./bw-mon eth0 'ip src 10.0.0.1 and esp'
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <pthread.h>

#ifndef IPTOS_ECN_MASK
#define IPTOS_ECN_MASK 0x03
#endif

// Time in msec between load reports of bw-mon
const unsigned int REPORT_INTERVAL = 200;


struct timeval last_time;		/* last time we saw a packet */
struct timeval first_time;	/* time of first packet, for total stat */
unsigned int delay = 0;			/* delay between packets */
unsigned long size_ival=0;    /* amount of data seen in interval */
unsigned long size_total=0;   /* amount of data seen in total */

const unsigned int USEC_PER_MSEC = 1000;
const unsigned int USEC_PER_SEC = 1000*1000;

// returns a-b in mikroseconds
long timeval_diff(const struct timeval *a, const struct timeval *b) {

	return (USEC_PER_SEC*(a->tv_sec - b->tv_sec) +
			(a->tv_usec - b->tv_usec));
}

void throughput_cb(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet) {
	
	struct ethhdr *eh = (struct ethhdr*)packet;
	struct iphdr *iph = (struct iphdr*)(packet+sizeof(struct ethhdr));

	if (eh->h_proto == ntohs(ETH_P_IP) && iph->version == 4) { // is it IPv4?
		size_ival += 8*ntohs(iph->tot_len);
	}
}

void metadata_cb(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet) {
	
	struct ethhdr *eh = (struct ethhdr*)packet;
	struct iphdr *iph = (struct iphdr*)(packet+sizeof(struct ethhdr));

	delay = (USEC_PER_SEC*(hdr->ts.tv_sec - last_time.tv_sec) +
			(hdr->ts.tv_usec - last_time.tv_usec));
	last_time = hdr->ts;

	if (eh->h_proto == ntohs(ETH_P_IP) && iph->version == 4) { // is it IPv4?

		printf("IPD:%08d, len:%05d, ECN=%01x DS=%03x, ID=%05d, offset=%04x, ttl=%03d, proto=%02d\n", 
				delay,
			 	ntohs(iph->tot_len),
				iph->tos & IPTOS_ECN_MASK,
				iph->tos << 3,
			 	ntohs(iph->id),
			 	ntohs(iph->frag_off),
			 	iph->ttl,
				iph->protocol);
		size_total += 8*ntohs(iph->tot_len);
	}
 	else
		printf("non-ipv4: IPD:%05d, len:%04d, eth_type=%04x ver=%d,\n",
			 	delay,
			 	hdr->len,
			 	ntohs(eh->h_proto),
			 	iph->version);

}

/* Basic signal handler: closes something on exit */
static void sig_handler(int signum) {

	gettimeofday(&last_time, NULL);
	long runtime = timeval_diff(&last_time,&first_time);
	printf("\nCaught signal ...\n");
	printf("\nTotal: %lu Mbytes in %ld seconds, or %.2f MBit/s\n\n",
			size_total/8/1024/1024,
			runtime/USEC_PER_SEC,
			(double)size_total/(double)runtime);
	exit(1);

}

void usage(char *name) {

	printf("\n");
	printf("Usage: %s <iface> <rule>\n",name);
	printf("\n");
	printf("\t<iface>\tinterface to listen on\n");
	printf("\t<rule>\tlibpcap traffic filter rule\n\n\n");
	exit(1);
}

void *reporter_thread(void *arg) {

	time_t now;
	unsigned long bytes=0;  /* amount of data seen in interval */

	usleep(REPORT_INTERVAL*USEC_PER_MSEC);
	while(1) {
		bytes = size_ival; /* who needs locking..? */
		size_ival -= bytes;
		size_total += bytes;
		now = time(NULL);
		printf("%ju %.02f MBit/s\n", (uintmax_t)now, (double)bytes/1000/(double)REPORT_INTERVAL);
		usleep(REPORT_INTERVAL*USEC_PER_MSEC);
	}

}

int main(int argc, char *argv[])
{
	char *mode = argv[0];       /* Name of this binary, cc-mon or bw-mon? */
	char *dev = argv[1];			  /* The device to sniff on */
	char *filter_exp = argv[2];	/* The filter expression */
	
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;			/* The compiled filter */
	pcap_t *handle;					    /* Session handle */
	bpf_u_int32 mask;				    /* Our netmask */
	bpf_u_int32 net;				    /* Our IP */
	struct pcap_pkthdr hdr;			/* The header that pcap gives us */
	const u_char *packet;			  /* The actual packet */
	pthread_t reporter; 			  /* timed reporting of measurements */
	
	if (argc < 3)
		usage(mode);
	
	// print given command, so that we can log everything by redirecting to a file
	printf("%s ",argv[0]);
	printf("%s ",argv[1]);
	printf("%s\n\n",argv[2]);
	
	// remove possible prepended paths
	mode += (strlen(mode) - strlen("cc-mon"));

	/* signal handler will close nfq hooks on exit */
	if(signal(SIGINT, sig_handler) == SIG_IGN)
		signal(SIGINT, SIG_IGN);
	if(signal(SIGHUP, sig_handler) == SIG_IGN)
		signal(SIGINT, SIG_IGN);
	if(signal(SIGTERM, sig_handler) == SIG_IGN)
		signal(SIGINT, SIG_IGN);

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session, no promiscuous mode: they're our packets */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	/* init time spec */
	gettimeofday(&last_time, NULL);
	gettimeofday(&first_time, NULL);

	/* loop in chosen mode until sigint */
	if (0 == strcmp("bw-mon", mode)) {
		pthread_create(&reporter, NULL, reporter_thread, NULL);
		pcap_loop(handle, -1, throughput_cb, NULL);
	}
	else {
		pcap_loop(handle, -1, metadata_cb, NULL);
	}

	pcap_close(handle);

	exit(0);
}
