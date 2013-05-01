/*
 * UDP Packet Generator
 * Copyright (c) 2010-2012 Steffen Schulz
 *
 * Read lines as "delay size" from stdin and send appropriate packets to host:port
 *
 * Usage
 *       cat input | udpgen <host> <port>
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#define DEBUG 0


/* Basic signal handler closes nfq hooks on exit */
static void sig_handler(int signum) {
  
  printf("\nCaught Signal ...\n\n");
  exit(0);
}

static void usage() {
  printf("\nUsage:\n\tudpgen <host> <port>\n");
  exit(1);
}


int main(int argc, char **argv) {
  
  struct sockaddr_in sin;
  struct hostent *peer;

  unsigned int len = 0;
  unsigned int cc_ipd = 0;
  unsigned int cc_size = 0;
  unsigned int size = 0;
  unsigned int cntr = 0;
  unsigned int port = 0;
  int sfd = 0;
  
  if (argc != 3)
    usage();

  /* Pseudo data that we send in each packet.
   * Maximum packet size larger than ethernet MTU probably doesnt make sense
   * For performance, we actually want small packets and high packet rate..
   */
  char buf[1500];
  memset(buf,'x',sizeof(buf));


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
  

  /* open network socket */
  sin.sin_family      = AF_INET;

  port = atoi(argv[2]);
  sin.sin_port        = htons(port);

  peer = gethostbyname(argv[1]);
  bcopy (peer->h_addr, &(sin.sin_addr.s_addr), peer->h_length);

  sfd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sfd == -1) {
	  fprintf(stderr, "Got no socket..\n");
	  exit(1);
  }
    
  /* send data to peer until killed */
  while (1) {
	  
    len = fscanf(stdin,"%u %u\n",&cc_ipd, &cc_size);

    if (len != 2) {
      if (DEBUG)
	printf("bad input\n");
      cc_ipd = 20000;  /* default delay in usec */
      cc_size = 20;   /* default size in byte */
    }

    if (cc_size==0) {
       fprintf(stderr, "Auto-exit on 0 size payload request.\n");
       exit(1);
    }
    
    usleep(cc_ipd);
    
    /* Dont send more than we have :-) */
    if (cc_size > sizeof(buf)) {
      fprintf(stderr,"WARN: Attempting to send more than 1500 Byte packet..\n");
      cc_size = sizeof(buf);
    }

    sendto(sfd, buf, cc_size, 0, (struct sockaddr*)&sin, sizeof(sin));
  }
}
