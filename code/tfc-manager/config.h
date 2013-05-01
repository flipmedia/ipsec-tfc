#ifndef TRADEOFF_CONFIG_H
#define TRADEOFF_CONFIG_H

/* TFC Management Configuration */

const char          TFC_SYSCTL_ROOT[] = "/proc/sys/net/ipv4/tfc";

// TFC Management policy parameters
const unsigned int  MAX_BANDWIDTH = 200;      	// max bandwidth to use, in Mbits

const unsigned int  OVERFLOW_THRESHOLD = 1;   	// when to react on queue overflow, in pkt/sec
const unsigned int  UNDERFLOW_THRESHOLD = 400;	// when to react on queue underflow, in pkt/sec
const unsigned int  MIN_DELAY = 200;          	// minimum IPD in usec
const unsigned int  OPT_DELAY = 400;          	// optimum IPD in usec, used to get best pkt_send_num
const unsigned int  MAX_DELAY = 10000;         	// maximum IPD in usec
		
// TFC size = WAN PMTU - IP - worst-case-ESP - IP = 1500 - 20 - 12+ENC/AUTH-overhead  - 20 ~= 1420
// MUST SET MTU TO ALSO AVOID FRAGMENTATION 
// -> rfc4106(gcm(aes)/1500 -> LAN:1417, TFC: 1423
const unsigned int  MAX_LAN_PKT_SIZE = 1423;  	// data + TFC + ESP + IP <= WAN PMTU
const unsigned int  MIN_LAN_PKT_SIZE = 25;    	// data = IP + x
	
const unsigned int  MAX_QUEUE_LEN = 50000;      // max queue len, in pkts
const unsigned int  MIN_QUEUE_LEN = 5;       		// min queue len, in pkts. Overrides QUEUE_TRAVERSAL_LIMIT if != 0
const unsigned int  MAX_QUEUE_TIME = 5000;      // max time for packet to get through TFC queue, in msec
const unsigned int  OPT_QUEUE_TIME = 500;      	// max time for packet to get through TFC queue, in usec

// Mode Security parameters. We use leaky bucket model. This means allowed
// changes are collected and can be used later, even in "bursts" if needed.
const unsigned int  MODE_SEC_START_TOKENS = 20; // allowed initial changes to adapt to current traffic
unsigned int        MODE_SEC_TOKEN_RATE = 5; 	// seconds between mode change
const unsigned int  MODE_SEC_BURST_MAX = 30;   	// max num of buckets to keep for bursts
const unsigned int  RATE_STOP_TOKENS = 6; 			// Before stopping, collect some tokens to quickly restart
const unsigned int  RATE_DECREASE_TOKENS = 14; 	// Before slowing, collect some tokens to quickly recover
const unsigned int  SIZE_DECREASE_TOKENS = 15; 	// Before slowing, collect some tokens to quickly recover
const unsigned int  RATE_DECREASE_DELAY = 3; 		// how long to wait before we decrease rate, in seconds
const unsigned int  SIZE_DECREASE_DELAY = 5;  	// how long to wait before we decrease size, in seconds

const unsigned int  MODE_SEC_RATE_QUANT = 1000; // granularity at which pkt rate is adjusted, in pkt/s
const unsigned int  MODE_SEC_SIZE_QUANT = 100; 	// granularity at which pkt size is adjusted, in bytes


#endif
