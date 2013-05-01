/*
 * CC Socket - A Covert Channel Socket Frontend
 * Copyright (c) 2010-2012 Steffen Schulz
 *
 * Wrapper around covert channel base tools.
 * Provides a port on each endpoint where data can be sent/received.
 *
 * The effect is similar to ssh portforwarding, except we tunnel the data
 * through a covert channel. We use a socket instead of tun/tap to spare
 * ourselves the overhead of IP headers etc.
 * 
 * (As far as I remember, this was not really working yet.)
 *
 * Usage:
 *
 * cc -o ccsocket ccsocket.c
 * ./ccsocket 2008  ./ipd "./pmon eth1 'ip src 10.0.0.2 and esp'" "20000,10000,4000,3000"
 *
 * 
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <string.h>
#include <strings.h>

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>

#include <signal.h>
#include <math.h>
#include <assert.h>


const int DEBUG = 1; // debug?
const size_t BUF_SIZE = 500; // some platform specific buffer size
FILE *send_stream;
FILE *recv_stream;


char help_msg[] = "Usage: \n \
\n \
  ccsocket <listen port> <sender binary> <recver binary> <symbols list> \n \
\n \
\n \
  listen port:   Network port at localhost to bind the socket to. \n \
\n \
  symbol list:   A comma-separated list of 2^x symbols that represent the \n \
                 symbol space. E.g., '1,2,3' for a channel that encodes bits {0,1} \n \
				 as symbols {2,3}, with x=2. \n		\
\n									\
  sender binary: A tool that sends symbols from the symbol list over some covert \n \
                 channel, e.g., enforces some inter-packet delay on forwarded \n \
                 traffic. Input is provided one symbol per line on stdin. \n \
\n									\
  recver binary: A tool that reads symbols from some covert channel and prints \n \
                 the the identified code symbol to stdout, one symbol per line. \n \
                 Symbols should be part of <symbols list> \n \
\n									\
  ccsocket should be started with the same parameters on both endpoints. Each \n \
  endpoint starts a CC sender and receiver, thus providing full duplex. \n\n";


void fail(char *msg) {

  fprintf(stderr,"Fatal error: %s\n\n",msg);

  exit(1);
}
  
void usage(int ret) {

  fprintf(stdout,"%s\n",help_msg);

  exit(ret);

}

int open_socket_or_die(const char *port) {

  struct addrinfo hints;
  struct addrinfo *res;
  int sfd,ret;

  memset(&hints, 0, sizeof hints);

  hints.ai_family = AF_INET;        // IPv4
  hints.ai_socktype = SOCK_DGRAM;   // UDP
  hints.ai_flags = AI_PASSIVE;      // outsourced to kernel

  if ((ret = getaddrinfo(NULL, port, &hints, &res)) != 0)
    fail("Error in getaddrinfo()");

  if ((sfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
    fail("Unable to open socket, look some more at res[] list..");
  
  if ( bind(sfd, res->ai_addr, sizeof(struct sockaddr_in)) == -1)
    fail("Unable to bind socket..");

  freeaddrinfo(res); // free

  return sfd;

}

/* Check supplied parameters, die on error.. */
int parameters_are_sensible(int argc, int port, const char *cc_sender, const char* cc_recver) {

  if (argc != 5) {
    fprintf(stderr, "Bad number of arguments: %d\n\n",argc);
    usage(0);
  }

  if (port < 1 || port > 65535) {
    fprintf(stderr, "Bad port parameter %d\n",port);
    usage(1);
  }

  FILE *s,*r;
  char *send_bin = strndup(cc_sender,(index(cc_sender,' ')-cc_sender));
  char *recv_bin = strndup(cc_recver,(index(cc_recver,' ')-cc_recver));


  if (!(s = fopen(send_bin, "r"))) {
    fprintf(stderr, "Can't open file \"%s\"\n",send_bin);
    usage(1);
  }

  if (!(r = fopen(recv_bin, "r"))) {
    fprintf(stderr, "Can't open file \"%s\"\n",recv_bin);
    usage(1);
  }

  fclose(s);
  fclose(r);

  return 1;
}

/* Basic signal handler: kill childs on exit */
static void sig_handler(const int signum) {

  printf("\nCCsocket caught signal ...\n\n");

  pclose(send_stream);
  pclose(recv_stream);
  exit(0);
}

/* Loop: read from socket and send via stdin of cc-sender
 *
 * Need to slice bytes according to available symbol space. Also, recvfrom()
 * might return more or less bits than what we can encode at once, so we need to
 * buffer. For simplicitly, bitchunk must be 8 (or maybe 16) for now.
 */
int send_loop(int ssize, char **cb, FILE *send_stream, const int sfd) {

  size_t nread;
  char *buf = calloc(sizeof(char),BUF_SIZE); // almost-a-ringbuffer
  char *buf_pos; 		// current fill position of buffer
  char *buf_start; 	// points to what still needs processing, up until buf_pos
  size_t len; 			// remaining yet unprocessed bytes in buffer.
  size_t processed;
  char data = 0;
  int i;

  buf_start = buf_pos = buf;	// buffer is emty
  len = 0; 

  for (;;) {

    nread = recvfrom(sfd, buf_pos, BUF_SIZE - len , 0, NULL, NULL);
		
    if (DEBUG)
      printf("SEND got %ld bytes from socket..\n", (long) nread);

    if (nread == -1)
      continue;               /* Ignore failed request */
    
    len += nread;
    while (len*8 >= ssize) {

      /* Process <bitchunk> bits at once from buffer, increase buf_start up
       * to buf_pos and decrease nread.
       */

      //fprintf(stderr, "buf_start[0]: %d\n", buf_start[0]);

      data = buf_start[0];
      if (DEBUG)
	printf("SEND byte: %x\n",data);
      for (i = 0; i<8; i++) {
	if (DEBUG)
	  fprintf(stderr,"SEND cb[bit]: %s\n",cb[ data & 0x01 ]);
	fprintf(send_stream,"%s 0\n",cb[ data & 0x01 ]);
	data = data >> 1;
      }

      //fprintf(send_stream,"%s\n",cb[ buf_start[0] ]);
      buf_start++;
      len--;
    }

    buf_pos = buf_start+len;
    fflush(send_stream);
  }
}

/* Loop: read from cc-receiver stdout and and write to socket */
int recv_loop(int ssize, char **cb, FILE *recv_stream, const int sfd) {

  // struct sockaddr_storage peer_addr;
	
  int i, bit;
  size_t len;
  unsigned int cc_ipd, cc_size;
  char data = 0; 

  bit = 0;

  while (! (feof(recv_stream))) {

    len = fscanf(recv_stream,"%u %u\n",&cc_ipd,&cc_size);

    if (DEBUG)
      printf("RECV ipd=%d size=%d\n",cc_ipd,cc_size);

    for (i = 0; i < ssize; i++) {
      if ( cc_ipd - atoi(cb[i]) < 500 ) {
	if (DEBUG)
	  printf("RECV got sym num: %d\n",i);
	data |= i;
	data = data << 1;
	bit++;

	if (bit == 7) {
	  bit = 0;
	  if (DEBUG)
	    printf("RECV got byte: %x\n",data);
	}
      }
    }
  }

  /* if (sendto(sfd, buf, nread, 0, */
  /* 	     (struct sockaddr *) &peer_addr, */
  /* 	     peer_addr_len) != nread) */
  /*   fprintf(stderr, "Error sending response\n"); */

}


/* parse string of comma-separated strings and return as array of strings */
char **get_symbol_list(int *num, char *list) {

  char *pos;
  char **cb;
  unsigned int i,j,c;

  /* count number of delimeters */
  pos = list;
  for (i = 1; (pos = index(pos+1,',')); i++);

  if (DEBUG)
    printf("CB: trying to parse list with %d entries\n", i);

  /* alloc codebook table */
  cb = calloc( sizeof(char*), i);
  *num = i;

  /* Fill the array */
  for (j = 0; (j < i) && (pos = strtok(list, ",")); j++) {
    list = NULL; // must be NULL for subsequent calls to strtok above

    cb[j] = calloc( sizeof(char), strlen(pos));
    if (DEBUG)
      printf("CB: adding codebook entry %d = %s\n",j,pos);
    strcpy(cb[j],pos);
  }

  return cb;
}

/* return highest n <= x such that n = 2^k, k € |N */
unsigned int closest_smaller_2exp (unsigned int x) {

  x = (trunc(log(x)/log(2))); 
  return exp2(x);
}


/* Fill the codebook
 * 
 * For simplicty and performance, we generate a lookup-table for byte-wise sending
 * First, generate lists of IPDs and Sizes, then combine them to create all symbols
 * Then fill codebook for all 256 possible values of a byte with combination of symbols
 */
int generate_code_book (int *symsize, char *syms) {

  char *pos;
  unsigned int i,j,x,n;
  unsigned int space;
  char **ipd_cb;
  char **size_cb;
  char **cb;
  unsigned int ipds, sizes;
  

  // format of <syms> = ipd1,ipd2,...,ipdN x size1,size2,...,sizeN
  pos = strtok(syms, "x");
  ipd_cb = get_symbol_list(&ipds,pos);

  pos = strtok(NULL, "x");
  size_cb = get_symbol_list(&sizes,pos);


  /* Reduce symbol space to 2^x for some x>=2.
   * Then figure out how many symbols we need to represent 1 byte.
   * 2^x = 2^(a+b) = 2^a * 2^b => ipds = 2^a, sizes = 2^b
   */
  ipds = closest_smaller_2exp(ipds);
  sizes = closest_smaller_2exp(sizes);
  space = ipds*sizes;

  /* Implementation limit: limit space to 256
   * (Yes, the loop is ugly...but look how quick it is to write...and it works!) */
  while (space>256) {

    fprintf(stderr,"CB: Warning: Symbol space is larger than supported, reducing to 256..\n");
    if (ipds>sizes)
      ipds = closest_smaller_2exp(--ipds);
    else
      sizes = closest_smaller_2exp(--sizes);

    space = ipds*sizes;
  }

  if (space < 2)
    fail ("Symbol space smaller than 1 bit?");

  /* How many symbols to send to encode one byte?
   * space = 2^x, find n such that 2^(n*x) = 256 => n = 8/x
   */

  x = round(log(space)/log(2)); // amount of bits we can encode in one symbol

  if (0 != 8%x)
    fprintf(stderr,"Note: Unable to partition one byte into multiple symbols w/o overhead.\n");

  n = ceil(8/x); // number of symbols needed to encode one byte


  /*
   * Finally, create the actual codebook, the actual purpose of this function...
   * Each entry in table is a string of n symbols, separated by \n.
   */


  /* alloc codebook table for encoding a byte => 256 fields */
  cb = calloc(sizeof(char*),256);

  // cb[j] = <j_1 * ipds, j_2 * sizes, j_3 * n> ?

  char sym[500];
  char sym1[500], sym2[500], sym3[500], sym4[500];

  for (num=0; num < n; num++ ) {
    for (ipd=0; ipd < ipds ; ipd++) {
      for (size=0; size < sizes; size++) {

	sym1 = ipd_cb[ipd] | size_cb[size]


    cb[j] = calloc(sizeof(char), strlen(pos));
    if (DEBUG)
      printf("CB: adding codebook entry %s\n",pos);
    strcpy(cb[j], pos);
  }

  

  // return number of symbols, needed for bit-slicing later on
  *symsize = i;
  return cb
}

main(int argc, char **argv) {

  if (argc < 5 )
    usage(1);

  const char* port 			= argv[1];
  const char* cc_sender = argv[2];
  const char* cc_recver = argv[3];
  char* symbols = argv[4];
  char **codebook = NULL;
  int symsize = 0;

  /* check if parameters appear sensible or die */
  parameters_are_sensible(argc,atoi(port),cc_sender,cc_recver);


  printf("CB-test: cb: %x\n", codebook);
  /* populate binary<->symbol code book */
  codebook = generate_code_book(&symsize,symbols);
	
  if (DEBUG) {
    int x;
    for (x = 0; x< symsize; x++) {
      printf("CB-test: cb[%d]: %s\n",x, codebook[x]);
    }
  }
  
  if ((symsize < 2) || ((symsize %2) != 0)) {
    fprintf(stderr,"Error when generating codebook, check <symbol> parameter.\n");
    usage(1);
  }
  
  /* We encode x = 2^symsize bits at once. BUF_SIZE *must* be larger than
   * symsize.
   */
  if (symsize >= BUF_SIZE*8)
    fail("Cannot do. Please, increase BUF_SIZE or adjust symbol space.");
			
  // assume this for now..
  assert(symsize == 8);

  /* open the network socket to listen to or die */
  const int sfd = open_socket_or_die(port);

  /* signal handler will cleanup on exit */
  if(signal(SIGINT, sig_handler) == SIG_IGN)
    signal(SIGINT, SIG_IGN);
  if(signal(SIGHUP, sig_handler) == SIG_IGN)
    signal(SIGINT, SIG_IGN);
  if(signal(SIGTERM, sig_handler) == SIG_IGN)
    signal(SIGINT, SIG_IGN);

  /* spawn program and use attach its stdin/stdout to a file stream */
  if (!(send_stream = popen(cc_sender,"w")))
    fail("Failed to launch sender app...");
  if (!(recv_stream = popen(cc_recver,"r")))
    fail("Failed to launch receiver app...");

  if (!send_stream || !recv_stream) {
    fprintf(stderr, "Unable to start and connect to helper tools for CC send/recv. Exit.\n");
    exit(1);
  }

  if (fork())
    send_loop(symsize,codebook,send_stream,sfd);
  else
    recv_loop(symsize,codebook,recv_stream,sfd);
}
