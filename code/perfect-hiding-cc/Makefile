
all: sidechannel noise tcpgen udpgen

sidechannel: sidechannel.c
	cc -o sidechannel -lrt -lnetfilter_queue sidechannel.c

udpgen: udpgen.c
	cc -o udpgen udpgen.c

tcpgen: tcpgen.c
	cc -o tcpgen tcpgen.c

noise: noise.c
	cc -o noise -lrt -lnetfilter_queue noise.c

clean:
	rm sidechannel noise tcpgen udpgen
