#ifndef TRADEOFF_H
#define TRADEOFF_H

#include "config.h"

const unsigned int  BIT_PER_MBIT = 1000000;
const unsigned int  USEC_PER_SEC = 1000000;
const unsigned int  MSEC_PER_SEC = 1000;
const unsigned int  USEC_PER_MSEC = 1000;

const unsigned int  TFC_OVERHEAD = 14;           // TFC header, 12 byte or 16 with fragm header
const unsigned int  IPSEC_OVERHEAD = 10+12+2+20; // TFC-to-WAN overhead: ESP+MAC+padding+IP header


typedef u_int32_t key;            // IPv4 LAN client address

enum { false = 0, true = 1};

struct tfc_variable {
	char *name;
	unsigned int num; // num of data points in this variable
	unsigned long value[10]; // max variables per sysctl file
};

struct client {
	struct client *next;
	struct client *last;
	key           id;
	u_int32_t     size_vote;  /* what size does this client want right now? */
	u_int32_t     rate_vote;  /* what rate does the client want right now?  */
	u_int32_t     votes;      /* how much does this client influence votes? */
};

struct config {
	double timeout;
	char *dirname;
	char *devname;
	char *filter;
	double tokens;
	FILE *socket;
	long rate_decrease_cntr;
	long size_decrease_cntr;
	struct client *clients;
	double avg_size;
	double avg_rate;
};

#endif
