
all: ipd cc-mon bw-mon udpgen red-table

clean:
	rm -f ccsocket ipd cc-mon bw-mon udpgen red-table

ccsocket: ccsocket.c
	cc -o ccsocket ccsocket.c

ipd: ipd.c
	cc -o ipd -l netfilter_queue -l rt ipd.c

bw-mon: pcap-monitor.c
	cc -o bw-mon -lpcap -lpthread pcap-monitor.c

cc-mon: bw-mon
	test -x cc-mon || ln bw-mon cc-mon

udpgen: udpgen.c
	cc -o udpgen udpgen.c

red-table: red-table.c
	cc -lm -std=c99 -o red-table red-table.c
