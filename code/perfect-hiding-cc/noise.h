/*
 * Hooks into Linux netfilter infrastructure and delay packets
 * based in input from third party(side-channel data source).
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


int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
		                            struct nfq_data *nfa, void *data);

static void sig_handler(int signum);

static int fail(char *str);
