/*
 * Proto-Prototype implementation of a TFC Manager.
 * 
 * Copyright (c) 2010-2012 Steffen Schulz (not proud of it)
 *
 * Implements Mode Security trade-off with a token bucket filter. Also keeps
 * statistics on LAN traffic to implement the Threshold-Secure trade-off scheme.
 * 
 * The Threshold-Secure TFC subsystem can be disabled by setting the expected
 * number of Insiders to the number of clients in the LAN.
 * 
 * Inbound IPD can be managed by having the respective peer transmit its outbound
 * IPD settings. Currently this is done using a simple TCP/IP connection, a
 * regular implementation should of course authenticate these messages.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#include "tradeoff.h"
#include "config.h"

#if 0
#define debug(fmt, args...)  printf(fmt, ## args)
#define stats(fmt, args...)  printf(fmt, ## args)
#else
#define debug(fmt, args...)  { }
#define stats(fmt, args...)  { }
#endif

#define info(fmt, args...)  printf(fmt, ## args)
#define modesec(fmt, args...)  printf(fmt, ## args)
#define notice(fmt, args...)  fprintf(stderr, fmt, ## args)
#define error(fmt, args...)  fprintf(stderr, fmt, ## args)
#define tell(fmt, args...)  printf(fmt, ## args)


void generate_tokens(struct config *conf)
{
	conf->tokens += (float)conf->timeout/(float)MODE_SEC_TOKEN_RATE;
	if (conf->tokens > MODE_SEC_BURST_MAX)
		conf->tokens = MODE_SEC_BURST_MAX;
	modesec("Tokens: %.2f\n",conf->tokens);
}

double max(double x, double y) 
{
	if (x > y)
		return x;
	else
		return y;
}
	
int equal(double x, double y) 
{
	return (abs(x - y) < 1);
}

struct client *find_client(struct client* head, key *id)
{
	struct client *cli = head->next;

	while (cli->id != *id && cli->next != head)
		cli = cli->next;

	if (cli->id == *id)
		return cli;
	else
		return NULL;
}

struct client *add_client(struct client *head, key *id)
{
	struct client *new;

	debug("adding new client %d.%d.%d.%d\n",
			htonl(*id)>>24 & 0xFF,
			htonl(*id)>>16 & 0xFF,
			htonl(*id)>>8  & 0xFF,
			htonl(*id)     & 0xFF);

	new = malloc(sizeof(struct client));
	if (!new)
		return NULL;

	new->next       = head;
	new->id         = *id;
	new->size_vote  = 0;
	new->rate_vote = 0;
	new->votes = 0;

	// add to end of list
	head->last->next = new;
	head->last = new;
	head->id++; // count num of clients

	debug("Now have %d clients.\n",head->id);

	return new;
}

int get_tfc_state(char *tfc_dir, struct tfc_variable *tfc)
{
	unsigned int i = 0, pathlen = 0, arg = 0;
	char filename[200] = "";
	FILE *fp;

	strcat(filename, tfc_dir);
	pathlen = strlen(filename);

	while (tfc[i].name != NULL) {
		stats("Getting tfc_state variable %16s: ", tfc[i].name);
		fp = fopen(strcat(filename, tfc[i].name), "r");
		if (!fp) {
			error("\nError opening sysctl file %s\n", filename);
			return false;
		}

		// fp is okay, read content into tfc[i].value[]
		for (arg = 0; arg < tfc[i].num-1; arg++) {
			fscanf(fp, "%lu\t", &tfc[i].value[arg]);
			stats(" %lu, ", tfc[i].value[arg]);
		}
		fscanf(fp, "%lu", &tfc[i].value[arg]);
		stats(" %lu\n", tfc[i].value[arg]);

		i++;
		fclose(fp);
		filename[pathlen] = 0;
	}
}

int set_tfc_state(struct tfc_variable *vars, struct config *conf)
{
	unsigned int i = 0, pathlen = 0, arg = 0;
	char filename[200] = "";
	char buf[200];
	FILE *fp;

	strcat(filename, conf->dirname);
	pathlen = strlen(filename);

	debug("\n");
	while (vars[i].name != NULL) {

		buf[0] = 0;
		filename[pathlen] = 0;
		
		debug("Setting tfc_state variable %s:\t", vars[i].name);
		fp = fopen(strcat(filename, vars[i].name), "w");
		if (!fp) {
			error("\nError opening sysctl file %s\n", filename);
			return false;
		}
		
		for (arg = 0; arg < vars[i].num-1; arg++) {
			sprintf(buf, "%s %lu", buf, vars[i].value[arg]);
			printf(" %lu,", vars[i].value[arg]);
		}
		sprintf(buf, " %lu", vars[i].value[0]);
		debug(" %s\n", buf);
		fprintf(fp, "%s\n", buf);

		
		// Hack: pretty-print everything that should be applied at remote party
		// as well. This should be done inside the IKEv2 tunnel. Or not at all.
		if (conf->socket) {
			if ((0 == strcmp(vars[i].name, "pkt_delay_avg")) ||
					(0 == strcmp(vars[i].name, "pkt_send_num"))) {
				fprintf(conf->socket, "%s=%s\n",filename,buf);
			}
		}
		
		fclose(fp);
		i++;
	}

	return true;
}

int reset_tfc_stats(struct config *conf)
{
	unsigned int i = 0, pathlen = 0, arg = 0;
	char filename[200] = "";
	char buf[200];
	FILE *fp;

	strcat(filename, conf->dirname);
	pathlen = strlen(filename);
	
	fp = fopen(strcat(filename, "stats_pkt_queue"), "w");
	if (!fp) {
		error("\nError opening sysctl file %s\n", filename);
		return false;
	}
	fprintf(fp, "0 0 0\n");
	fclose(fp);

	filename[pathlen] = 0;
	fp = fopen(strcat(filename, "stats_pkt_size"), "w");
	if (!fp) {
		error("\nError opening sysctl file %s\n", filename);
		return false;
	}
	fprintf(fp, "0 0 0\n");
	fclose(fp);

	return true;
}

void free_vars(struct tfc_variable *list)
{
	unsigned int i = 0;
	while (list[i].name != NULL) { 
		free(list[i].name);
		list[i].name = NULL;
		i++;
	}
}

long get_var(struct tfc_variable *list, char *name, unsigned int num)
{
	unsigned int i = 0;

	while (list[i].name != NULL) {
		if (0 == strcmp(list[i].name, name))
			return list[i].value[num];
		i++;
	}
	return -1;
}

void add_var(struct tfc_variable *vars, char *name,
	           unsigned int num, unsigned long val)
{
	unsigned int i = 0;

	while (vars[i].name != 0)
		i++;

	vars[i].name = strdup(name);
	vars[i].num = num;
	vars[i].value[0] = val;
	vars[i+1].name = NULL;
}

int mode_switch_is_allowed(struct config *conf) {
	
	if (conf->tokens >= 1) {
		conf->tokens--;
		debug("\tconsumed one token (%.2f tokens left)\n",conf->tokens);
		return true;
	}
	else {
		debug("\tnot enough tokens (%.2f tokens left)\n",conf->tokens);
		return false;
	}
}

int size_change_advisable(struct config *conf, unsigned int new_size, unsigned int cur_size)
{
	
	// size increase, reset decrease counter
	if (new_size > cur_size) {
		conf->size_decrease_cntr=0;
		return true;
	}
	
	// require a few consequtive decrease-requests before decreasing..
	conf->size_decrease_cntr++;

	// check if we have another token left to re-increase fast
	if (conf->tokens < SIZE_DECREASE_TOKENS)
		return false;

	// after sufficient delay, accept size decrease
	if (conf->size_decrease_cntr >= SIZE_DECREASE_DELAY/conf->timeout) {
		conf->size_decrease_cntr=0;
		return true;
	}
	
	return false;
}

unsigned int mode_sec_size_quantatizer(struct config *conf, unsigned int new_size)
{
	// new_rate is alwas an upper multiple of RATES_MODE_QUANT, or zero
	if (new_size != 0)
		new_size += (MODE_SEC_SIZE_QUANT - (new_size%MODE_SEC_SIZE_QUANT));
	
	return new_size;
}

double aggressive_increase(struct config *conf, double max_rate, double new_rate, double cur_rate)
{
	double amplifier;

	// rate increase with low tokens?
	if (new_rate <= cur_rate) { // XXX || (conf->tokens > MODE_SEC_MIN_STOP_TOKENS)
		return new_rate;
	}

#if 1
	debug("\tamplifier check: desired/max_rate: %4.0f / %4.0f\n", new_rate, max_rate);
	amplifier = (1.2*max_rate-cur_rate)/MODE_SEC_RATE_QUANT/conf->tokens;
	amplifier = ceil(amplifier);
	amplifier *= MODE_SEC_RATE_QUANT;
	
	if (amplifier <=0) {
		error("\n\tError, bad amplifier value?! amp: %.2f, max_rate: %.2d, new_rate: %.2f\n",amplifier, max_rate, new_rate);
		exit(1);
	}
#else
	amplifier = 2*MODE_SEC_RATE_QUANT;
#endif

	if (new_rate-cur_rate < amplifier) {
		new_rate = cur_rate + amplifier;
		new_rate += (MODE_SEC_RATE_QUANT - ((int)new_rate%MODE_SEC_RATE_QUANT));
	}
	
	debug("\tamplified_rate: %4.0f\n", amplifier+new_rate);
	
	if (new_rate > max_rate)
		new_rate = max_rate;
	
	return new_rate;
}
	
int rate_decrease_advisable(struct config *conf, double new_rate, double cur_rate)
{
	// rate increase, reset decrease counter
	if (new_rate > cur_rate) {
		conf->rate_decrease_cntr=0;
		return true;
	}

	// require a few consequtive decrease-requests before decreasing..
	conf->rate_decrease_cntr++;

	// don't stop if we have less than MIN_STOP tokens
	if (new_rate == 0 && conf->tokens < RATE_STOP_TOKENS)
		return false;

	// only decrease if we have more than MIN_DECREASE tokens
	if (conf->tokens < RATE_DECREASE_TOKENS)
		return false;

	// after sufficient delay, accept rate decrease
	if (conf->rate_decrease_cntr >= RATE_DECREASE_DELAY/conf->timeout) {
		conf->rate_decrease_cntr=0;
		return true;
	}
	
	return false;
}

// round up new_rate to a multiple of RATES_MODE_QUANT, or keep at zero
double mode_sec_rate_quantatizer(struct config *conf, double rate)
{
	unsigned long new_rate = floor(rate);

	if (new_rate != 0)
		new_rate += (MODE_SEC_RATE_QUANT - (new_rate%MODE_SEC_RATE_QUANT));
	return new_rate;
}

 // void tfc_adjust_rate_byReal(struct tfc_variable *new, struct tfc_variable *cur,
 // 	                                                   struct config *conf)
 // {
 // 	double cur_send_num  = get_var(cur, "pkt_send_num", 0);
 // 	double cur_delay     = get_var(cur, "pkt_delay_avg", 0);
 // 	double underflows    = get_var(cur, "stats_pkt_queue", 0)/conf->timeout;
 // 	double overflows     = get_var(cur, "stats_pkt_queue", 1)/conf->timeout;
 // 	unsigned int  padded        = get_var(cur, "stats_pkt_size", 0);
 // 	unsigned int  multis        = get_var(cur, "stats_pkt_size", 1);
 // 	unsigned int  frags         = get_var(cur, "stats_pkt_size", 2);
 // 	unsigned int cur_size= get_var(new, "pkt_len_avg", 0);
 // 	if (cur_size == -1)
 // 		cur_size= get_var(cur, "pkt_len_avg", 0);
 // 
 // 	double new_rate = 0;
 // 	double new_delay = 0;
 // 	double new_send_num = cur_send_num;
 // 	double cur_rate = cur_send_num*USEC_PER_SEC/cur_delay;
 // 	double avg_rate = conf->avg_rate/conf->timeout;
 // 	double max_rate = MAX_BANDWIDTH*BIT_PER_MBIT/(8*(cur_size+TFC_OVERHEAD+IPSEC_OVERHEAD));
 // 	
 // 	modesec("adjust_rate(): under/over/num: %4.1f/%4.1f/%2.1f, cur/avg_rate: %4.0f,%4.0f, ",
 // 			underflows, overflows, cur_send_num, cur_rate, avg_rate);
 // 	
 // 	// Startup condition.
 // 	// Cannot rely on TFC queue here (lags behind..) but cannot dismis it either
 // 	if (cur_send_num == 0) {
 // 		if (avg_rate != 0 || overflows) {
 // 			cur_send_num = new_send_num = 1;
 // 			new_rate = avg_rate + frags - multis;
 // 			goto check_setting;
 // 		}
 // 	}
 // 
 // 	// do we need lower or higher delays and how much?
 // 	if (overflows) {
 // 
 // 		if (overflows < OVERFLOW_THRESHOLD) {
 // 			notice("\n\toverflow-rate below threshold: %.2f, is the queue large enough?\n", overflows);
 // 			goto done;
 // 		}
 // 
 // 		new_rate = cur_rate + overflows/2;
 // 
 // 		// max packet rate is at bandwidth limit
 // 		if (new_rate > max_rate)
 // 				new_rate = max_rate;
 // 
 // 	}
 // 	else { // no overflows? -> check if we are too fast
 // 
 // 		// Stop condition. Only trigger if
 // 		// no packets on LAN && buffer empty && cur_rate is not very high
 // 		// Must not set new_delay too low, since new IPD values are only read at send event!
 // 		if (avg_rate == 0 && underflows >= avg_rate) {
 // 			//	&& underflows < UNDERFLOW_THRESHOLD) {
 // 			new_rate = 0;
 // 			new_send_num = 0;
 // 			new_delay = MAX_DELAY;
 // 			goto check_setting;
 // 			//underflows=0;
 // 		}
 // 
 // 		if (underflows < UNDERFLOW_THRESHOLD)
 // 			goto done;
 // 
 // 		// Decrease rate by going half way into threashold range
 // 		// (we want to avoid triggering followup increases/decreases of rate)
 // 		//new_rate = cur_rate-(underflows-UNDERFLOW_THRESHOLD/2);
 // 		new_rate = avg_rate + frags - multis;
 // 		
 // 		// Catch unexpected new_rate: If this ever happens, we missed the stop
 // 		// condition but the rate should be as low as possible.  check_settings will
 // 		// do the rest for us
 // 		if (new_rate <= 0)
 // 			new_rate = 0.000001;
 // 	}
 // 
 // check_setting:
 // 
 // 	modesec("new_rate: %4.0f, ", new_rate);
 // 	// quantatize for mode security
 // 	new_rate = mode_sec_rate_quantatizer(conf, new_rate);
 // 	modesec("quant: %4.0f, ", new_rate);
 // 	
 // 	// check decision history and possibly other stuff.
 // 	if (!rate_decrease_advisable(conf, new_rate, cur_rate)) {
 // 		modesec("\n\trate decrease not advisable.");
 // 		goto done;
 // 	}
 // 	
 // 	// make larger steps if low on tokens
 // 	new_rate = aggressive_increase(conf, max_rate, new_rate, cur_rate);
 // 	modesec("amplified: %4.0f, ", new_rate);
 // 	
 // 	// if channel not stopped, find compromise between IPD and pkt_send_num
 // 	if (new_rate > 0) {
 // 
 // 		// first, get pkt_send_num for optimal IPD
 // 		new_send_num = new_rate/(USEC_PER_SEC/OPT_DELAY);
 // 		if (new_send_num < 1)
 // 			new_send_num = 1;
 // 
 // 		// now re-compute IPD based on desired rate and optimum pkt_send_num
 // 		new_delay = USEC_PER_SEC/new_rate*new_send_num; // usec delay between underflows
 // 		while (new_delay < MIN_DELAY) {
 // 			modesec("\n\tdelay too low..num=%.2f, delay=%.2f", new_send_num, new_delay);
 // 			new_send_num++;
 // 			new_delay = (USEC_PER_SEC/new_rate)*new_send_num;
 // 			if (new_send_num > 200)
 // 				exit(1);
 // 		}
 // 		while (new_delay > MAX_DELAY) {
 // 			modesec("\n\tdelay too high: num=%.2f, delay=%.2f",new_send_num, new_delay);
 // 			if (new_send_num == 1) {
 // 				new_delay=MAX_DELAY;
 // 				break;
 // 			}
 // 			new_send_num--;
 // 			new_delay = (USEC_PER_SEC/new_rate)*new_send_num;
 // 		}
 // 	}
 // 	
 // 	if (equal(new_rate, cur_rate))
 // 		goto done;
 // 	
 // 	
 // 	if (!mode_switch_is_allowed(conf)) {
 // 		modesec("\n\tout of tokens!");
 // 		goto done; // can't apply new values!
 // 	}
 // 
 // 	stats("\n\told delay: %.1f, setting new delay: %.1f, new send num: %.1f\n",
 // 			cur_delay,
 // 			new_delay,
 // 			new_send_num);
 // 	stats("\n\tresulting new_rate: %.1f, vs. observed rate: %.1f",
 // 			USEC_PER_SEC*new_send_num/new_delay,
 // 			avg_rate);
 // 
 // save:
 // 	// store new config variables
 // 	modesec("\n\tmode switch: ratexnum=%4.0fx%.0f, delay:", new_rate,new_send_num,new_delay);
 // 	add_var(new, "pkt_send_num", 1, new_send_num);
 // 	add_var(new, "pkt_delay_avg", 1, new_delay);
 // done:
 // 	modesec("\n");
 // 	return;
 // }

void tfc_adjust_rate(struct tfc_variable *new, struct tfc_variable *cur,
	                                                   struct config *conf)
{
	double cur_send_num  = get_var(cur, "pkt_send_num", 0);
	double cur_delay     = get_var(cur, "pkt_delay_avg", 0);
	double underflows    = get_var(cur, "stats_pkt_queue", 0)/conf->timeout;
	double real_rate     = get_var(cur, "stats_pkt_queue", 1)/conf->timeout;
	double drops     		 = get_var(cur, "stats_pkt_queue", 2)/conf->timeout;
	unsigned int multis  = get_var(cur, "stats_pkt_size", 1);
	unsigned int frags   = get_var(cur, "stats_pkt_size", 2);
	unsigned int cur_size= get_var(new, "pkt_len_avg", 0);
	if (cur_size == -1)
		cur_size= get_var(cur, "pkt_len_avg", 0);

	double new_rate = 0;
	double new_delay = 0;
	double new_send_num = cur_send_num;
	double cur_rate = cur_send_num*USEC_PER_SEC/cur_delay;
	double avg_rate = conf->avg_rate;
	double max_rate = MAX_BANDWIDTH*BIT_PER_MBIT/(8*(cur_size+TFC_OVERHEAD+IPSEC_OVERHEAD));
	
	modesec("adjust_rate(): under/drops/num: %4.2f/%4.2f/%4.2f, cur/real/avg: %4.2f/%4.2f+%d-%d/%4.2f, ",
					underflows, drops, cur_send_num, cur_rate, real_rate, frags, multis, avg_rate);
	real_rate +frags - multis;
	

//	//// Startup condition.
//	// Need to start and scale real fast on connection starts..
//	if (cur_send_num == 0) {
//		if (avg_rate > 0 || real_rate > 0) {
//			new_send_num = 1;
//			new_rate = real_rate; // + MODE_SEC_RATE_QUANT; // = max( avg_rate, real_rate);
//			goto check_setting;
//		}
//	}
	
	//// Rate increase
	//if (avg_rate+frags-multis > 0.9*cur_rate)
	if (real_rate != 0 && (real_rate > 0.9*cur_rate || avg_rate > 0.95*cur_rate)) {
		new_rate = max(real_rate, cur_rate) + MODE_SEC_RATE_QUANT/2;
	//	new_rate += (real_rate - avg_rate)/2; // amplified
		goto check_setting;
	}
	// Decrease rate by going half way into threashold range
	// (we want to avoid triggering followup increases/decreases of rate)
	// new_rate = cur_rate-(underflows-UNDERFLOW_THRESHOLD/2);
	// new_rate = avg_rate + 0.00001; /// should not be zero
	else if (equal(avg_rate,0) && equal(real_rate,0)) {
		new_rate = 0;
		new_send_num = 0;
		goto check_setting;
	}
	else if (cur_rate > 0.8*avg_rate && real_rate <= avg_rate) {
		new_rate = avg_rate + MODE_SEC_RATE_QUANT/2;
		goto check_setting;
	}

	// no changes
	goto done;
	
//	//// Stop condition.
//	// Only trigger if no packets on LAN && buffer empty && cur_rate is not very high
//	// Must not set new_delay too low, since new IPD values are only read at send event!
//	// XXX new_rate is set to zero based on above decrease already, only have to
//	// care about send_num!
//	if (0 == floor(new_rate)) {
//		new_rate = 0;
//		new_send_num = 0;
//		new_delay = OPT_DELAY;
//		goto save_settings;
//	}

check_setting:

	modesec("new_rate: %3.0f, ", new_rate);
	// quantatize for mode security
	new_rate = mode_sec_rate_quantatizer(conf, new_rate);
	modesec("quant: %3.0f, ", new_rate);
	
	// max packet rate is at bandwidth limit
	if (new_rate > max_rate)
		new_rate = max_rate;
	
	// make larger steps when increasing with few tokens
	if (conf->tokens < RATE_STOP_TOKENS) {
		new_rate = aggressive_increase(conf, max_rate, new_rate, cur_rate);
		modesec("amplified: %3.0f, ", new_rate);
	}
	
	// if channel not stopped, find compromise between IPD and pkt_send_num
	if (new_rate > 0) {

		// first, get pkt_send_num for optimal IPD
		new_send_num = ceil(new_rate/(USEC_PER_SEC/OPT_DELAY));
		if (new_send_num < 1)
			new_send_num = 1;

		// now re-compute IPD based on desired rate and optimum pkt_send_num
		new_delay = USEC_PER_SEC/new_rate*new_send_num; // usec delay between underflows

		while (new_delay < MIN_DELAY) {
			modesec("\n\tdelay too low..num=%.2f, delay=%.2f", new_send_num, new_delay);
			new_send_num++;
			new_delay = (USEC_PER_SEC/new_rate)*new_send_num;
			if (new_send_num > 200)
				exit(1);
		}
		while (new_delay > MAX_DELAY) {
			modesec("\n\tdelay too high: num=%.2f, delay=%.2f",new_send_num, new_delay);
			if (new_send_num == 1) {
				new_delay=MAX_DELAY;
				break;
			}
			new_send_num--;
			new_delay = (USEC_PER_SEC/new_rate)*new_send_num;
		}

		new_delay = floor(new_delay);
	}

	//// Stop Condition
	// Zero delay means channel should stop
	if (new_delay == 0) {
		new_send_num = 0;
		new_delay = OPT_DELAY;
	}

save_settings:
	
	// would anything actually change?
	if (equal(new_send_num*USEC_PER_SEC/new_delay, cur_send_num*USEC_PER_SEC/cur_delay))
		goto done;
	
	// would it be advisable to change?
	if (!rate_decrease_advisable(conf, new_rate, cur_rate)) {
		modesec("\n\trate decrease not advisable.");
		goto done;
	}

	// can anything actually change?
	if (!mode_switch_is_allowed(conf)) {
		modesec("\n\tout of tokens!");
		goto done; // can't apply new values!
	}

	stats("\n\told delay: %.1f, setting new delay: %.1f, cur/new_send_num: %.1f/%.1f",
			cur_delay,
			new_delay,
			cur_send_num,
			new_send_num);
	stats("\n\tresulting new_rate: %.1f, vs. observed rate: %.1f",
			USEC_PER_SEC*new_send_num/new_delay,
			avg_rate);

	// store new config variables
	add_var(new, "pkt_send_num", 1, new_send_num);
	add_var(new, "pkt_delay_avg", 1, new_delay);
done:
	modesec("\n");
	return;
}
		
void tfc_update_stats(struct tfc_variable *new, struct tfc_variable *cur, struct config *conf)
{
	double real_rate     = get_var(cur, "stats_pkt_queue", 1)/conf->timeout;

	// collect overall traffic stats
	if (conf->clients->rate_vote > 0)
		conf->avg_size = conf->avg_size*0.2 + (conf->clients->size_vote/conf->clients->rate_vote)*0.8;
	conf->avg_rate = conf->avg_rate*0.7 + real_rate*0.3;

	debug("cur rate/size: %.2f/%.2f, avg: %.2f/%.2f\n",
			conf->clients->rate_vote/conf->timeout,
			conf->clients->size_vote/conf->clients->rate_vote,
			conf->avg_rate, conf->avg_size);

	return;
}

void tfc_adjust_size(struct tfc_variable *new, struct tfc_variable *cur, struct config *conf)
{
	unsigned int  cur_size      = get_var(cur, "pkt_len_avg", 0);
	unsigned int  padded        = get_var(cur, "stats_pkt_size", 0);
	unsigned int  multis        = get_var(cur, "stats_pkt_size", 1);
	unsigned int  frags         = get_var(cur, "stats_pkt_size", 2);
	unsigned int  new_size       = conf->avg_size;

	modesec("adjust_size(): size=%u, padded/mplex/frags: %u/%u/%u: ",
			cur_size, padded, multis, frags);

	// 1) every fragmented packet results in padding, unless multiplexed
	//padded -= (frags - multis);

	// In case this matches some currently dominant packet stream, calculate the
	// exakt packet size so that we can accomondate these packets. Other packets
	// can make this value a bit noisy, so add some surplus bytes to reduce
	// fragmenting rate. (should be more clever, e.g. use size to cover 80% of packets)
	new_size += TFC_OVERHEAD;
	new_size += new_size%8;  // pkt len in TFC is always multiple of 8 bytes!
	
	// quantatize for mode security
	modesec("new_size: %lu, ",new_size);
	new_size = mode_sec_size_quantatizer(conf, new_size);
	modesec("quant: %lu, ",new_size);
	
	if (new_size > MAX_LAN_PKT_SIZE)
		new_size = MAX_LAN_PKT_SIZE;
	if (new_size < MIN_LAN_PKT_SIZE)
		new_size = MIN_LAN_PKT_SIZE;
	
	if (new_size == cur_size)
		goto done;
	
	// check decision history and possibly other stuff.
	if (!size_change_advisable(conf, new_size, cur_size)) {
		modesec("\n\tchange not advisable..");
		goto done;
	}
	
	if (!mode_switch_is_allowed(conf)) {
		modesec("\n\tout of tokens!\n");
		goto done; // can't apply new values!
	}
	
save:
	modesec("new size: %d", new_size);

	// store new config variables
	add_var(new, "pkt_len_avg", 1, new_size);

done:
	modesec("\n");
	return;
}

void tfc_adjust_queue(struct tfc_variable *new, struct tfc_variable *cur, struct config *conf)
{
	double cur_rate;
	double cur_qlen     = get_var(cur, "pkt_queue_len", 0);
	double cur_qwrn     = get_var(cur, "pkt_queue_warn", 0);
	double new_qlen = cur_qlen;
	double new_qwrn = cur_qwrn;

	// if rate will be changed, compute qlen based on changed rate..
	double cur_send_num = get_var(new, "pkt_send_num", 0);
	double cur_delay    = get_var(new, "pkt_delay_avg", 0);
	
	if (cur_send_num == -1)
		cur_send_num = get_var(cur, "pkt_send_num", 0);

	if (cur_delay == -1)
		cur_delay    = get_var(cur, "pkt_delay_avg", 0);

	cur_rate = USEC_PER_SEC*cur_send_num/cur_delay;

	modesec("adjust_qlen(): cur_delay/cur_rate qlen/qwrn: %.0f/%.0f, %.0f/%.0f, ",
			cur_delay, cur_rate, cur_qlen, cur_qwrn);

	// adjust queue len with packet rate
	// -> low  packet rate means small queue, so new packets don't wait too long
	// -> high packet rate means larger queue, for get better bufferering and multiplexing
	// Rule of thumb:
	//  A new/unexpected packet must not need more than 100ms to through the queue.

	new_qlen = cur_rate*((double)MAX_QUEUE_TIME/(double)MSEC_PER_SEC);
	new_qwrn = cur_rate*((double)OPT_QUEUE_TIME/(double)USEC_PER_SEC);

	//tell("\n\tnew qlen/qwarn: %4.0f/%4.0f\n", new_qlen, new_qwrn);
	
	// make transisions smooth to reduce packet loss
	//new_qlen = 0.5*cur_qlen + 0.5*new_qlen;
	
	if (new_qlen < MIN_QUEUE_LEN) new_qlen = MIN_QUEUE_LEN;
	if (new_qlen > MAX_QUEUE_LEN) new_qlen = MAX_QUEUE_LEN;
	if (new_qwrn < MIN_QUEUE_LEN) new_qwrn = MIN_QUEUE_LEN;
	if (new_qwrn > MAX_QUEUE_LEN) new_qwrn = MAX_QUEUE_LEN;

	if (equal(new_qlen, cur_qlen) && equal(new_qwrn, cur_qwrn))
		goto done;

save:
	// XXX not required to check mode security limits here...right?
	modesec("new qlen/qwarn: %.0f/%.0f", new_qlen, new_qwrn);

	// store new config variables
	add_var(new, "pkt_queue_len", 1, new_qlen);
	add_var(new, "pkt_queue_warn", 1, new_qwrn);

done:
	modesec("\n");
	return;
}

// TFC manager main loop:
// observe stats->compute settings->set settings
void *tfc_manager(void *config)
{
	struct config* conf = (struct config*)config;
	struct tfc_variable tfc_cur[] = {
//		{ "pkt_burst_num",        1, 0 },
//		{ "pkt_burst_rate",       1, 0 },
		{ "pkt_send_num",         1, 0 },
		{ "pkt_queue_len",        1, 0 },
		{ "pkt_queue_warn",       1, 0 },
//		{ "pkt_len_algo",         1, 0 },
		{ "pkt_len_avg",          1, 0 },
//		{ "pkt_delay_algo",       1, 0 },
		{ "pkt_delay_avg",        1, 0 },
//		{ "pkt_delay_var",        1, 0 },
		{ "stats_pkt_queue",      3, 0 },
		{ "stats_pkt_size",       3, 0 },
		{ },
	};
	
	// tfc_variable[] is zero-terminated dynamic-sized list of variables
	struct tfc_variable tfc_new[sizeof(tfc_cur)/sizeof(struct tfc_variable)];
	
	// read TFC settings, reset overall settings
	get_tfc_state(conf->dirname, tfc_cur);

	while (true) { // while network_stats() is running..
		// reset tfc_new
		tfc_new[0].name = NULL;
		free_vars(tfc_new);
		conf->clients->rate_vote = 0;
		conf->clients->size_vote = 0;
		
		// wait to gather data (push would be better..)
		debug("sleeping %ld msec..\n", (long)(conf->timeout*MSEC_PER_SEC));
		usleep((long)(conf->timeout*USEC_PER_SEC));
		
		// update token bucket, read tfc status
		generate_tokens(conf);
		get_tfc_state(conf->dirname, tfc_cur);
		
		// compute new settings
		tfc_update_stats(tfc_new, tfc_cur, conf);
		tfc_adjust_size(tfc_new, tfc_cur, conf);
		tfc_adjust_rate(tfc_new, tfc_cur, conf);
		tfc_adjust_queue(tfc_new, tfc_cur, conf);

		// set new settings
		set_tfc_state(tfc_new, conf);
		reset_tfc_stats(conf);
		
	}
	pthread_exit(NULL);
}

/* Collect information about traffic seen from each LAN host.
 *
 * Every host(IP) is an element in a linked list, and the head of
 * the list collects overall statistics.
 */
void pcap_cb(u_char *clients, const struct pcap_pkthdr *hdr, const u_char *packet) {

	struct client *cli;
	struct client *list = (struct client*)clients;
	struct iphdr  *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));

	list->size_vote += hdr->len;
	list->rate_vote++;
	
	cli = find_client(list, &iph->saddr);
	if (!cli) {
		debug("pcab_cb: addclient()\n");
		cli = add_client(list, &iph->saddr);
		if (!cli) {
			error("Error adding client to list..exit.\n");
			exit(1);
		}
	}

	// add this packet to stats of client
	cli->rate_vote++; // XXX
	cli->size_vote+=hdr->len;
}

/*
 * Observe network via libpcap: Calls pcap_cb for each packet.
 */
void *network_stats(void *config)
{
	struct config *conf = (struct config*)config;
	pcap_t *handle;               /* Session handle */
	bpf_u_int32 mask;             /* Our netmask */
	bpf_u_int32 net;              /* Our IP */
	char errbuf[PCAP_ERRBUF_SIZE];/* Error string */
	struct bpf_program fp;        /* The compiled filter */

	/* Find the properties for the device */
	if (pcap_lookupnet(conf->devname, &net, &mask, errbuf) == -1) {
		error("pcap: Couldn't get netmask for device %s: %s\n",
			 	conf->devname, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(conf->devname, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL) {
		error("pcap: Couldn't open device %s: %s\n",
			 	conf->devname, errbuf);
		pthread_exit(NULL);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, conf->filter, 0, net) == -1) {
		error("pcap: Couldn't parse filter %s: %s\n",
			 	conf->filter, pcap_geterr(handle));
		pthread_exit(NULL);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		error("pcap: Couldn't install filter %s: %s\n",
			 	conf->filter, pcap_geterr(handle));
		pthread_exit(NULL);
	}

	/* loop until error */
	pcap_loop(handle, -1, pcap_cb, (void*)conf->clients);
	pcap_close(handle);

	error("NetworkStats: Exit.");
	pthread_exit(NULL);
}

/* Basic signal handler: closes something on exit */
void sig_handler(int signum) {

	error("\npcap-monitor caught signal ...\n\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	pthread_t pcap_thread;
	pthread_t tfc_thread;
	char path[200] = "";
	struct config conf;
	struct client *listhead;
	FILE *fp = NULL;

	if (argc < 5) {
		info("Usage: <interval> <socket> <tfc_dir> <devname> <filter>\n");
		info("\n");
		info("interval: Interval in milliseconds in which TFC is checked+adjusted.\n");
		info("socket:   Unix socket for network communication.\n");
		info("tfc_dir:  TFC sysctl subdirectory of the SA to manage.\n");
		info("devname:  LAN interface to listen on for packet statistics.\n");
		info("filter:   Libpcap filter string; applied when listening to LAN.\n");
		exit(1);
	}

	listhead = (struct client*)malloc(sizeof(struct client));
	listhead->next = listhead;
	listhead->last = listhead;
	listhead->id=0;

	strcat(path, TFC_SYSCTL_ROOT);
	strcat(path, "/");
	strcat(path,argv[3]);
	strcat(path, "/");
	
	fp = fopen(path, "r");
	if (!fp) {
		error("\nError opening given path %s\n", path);
		error("Check if TFC is running and correct path was given.\n");
		error("Waiting for sysctl interface to appear...\n\n");
	}	
	while (!fp) {
		error(".");
		sleep(2);
		fp = fopen (path, "r");
	}
	info("\nUsing TFC sysctl interface in %s, ival=%.2fms\n", path,conf.timeout);
	
	fp = fopen(argv[2], "w");
	if (!fp) {
		error("\nError opening given socket %s. Doing without.\n", socket);
	}

	conf.timeout = (double)atoi(argv[1])/(double)1000;
	conf.dirname = path;
	conf.devname = argv[4];
	conf.filter  = argv[5];
	conf.clients = listhead;
	conf.socket  = fp;
	conf.tokens  = MODE_SEC_START_TOKENS;

	if (argc > 6)
		MODE_SEC_TOKEN_RATE = atoi(argv[6]);

	/* signal handler will close nfq hooks on exit */
	if(signal(SIGINT, sig_handler) == SIG_IGN)
		signal(SIGINT, SIG_IGN);
	if(signal(SIGHUP, sig_handler) == SIG_IGN)
		signal(SIGINT, SIG_IGN);
	if(signal(SIGTERM, sig_handler) == SIG_IGN)
		signal(SIGINT, SIG_IGN);

	pthread_create(&tfc_thread, NULL, tfc_manager, (void*)&conf);
	//pthread_create(&pcap_thread, NULL, network_stats, (void*)&conf);
	network_stats((void*)&conf);
}
