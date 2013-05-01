#!/bin/bash

###
### Static part of TFC configuration
###

CMD="sysctl -w"
ROOT="net.ipv4.tfc"


################################

if [ "A$1" != "Apeer" ]; then
	IN=" ${ROOT}.10-0-1-1:2"
	OUT="${ROOT}.10-0-1-2:2"
else
	IN=" ${ROOT}.10-0-1-2:2"
	OUT="${ROOT}.10-0-1-1:2"
fi

$CMD $OUT.dummy_enable=1
$CMD $OUT.padding_enable=1
$CMD $OUT.fragmentation_enable=1
$CMD $OUT.multiplexing_enable=1
$CMD $OUT.pkt_queue_len=80
$CMD $OUT.pkt_queue_warn=50
$CMD $OUT.pkt_send_num=1

#$CMD  $IN.pkt_queue_len=150
#$CMD  $IN.pkt_queue_warn=20
#$CMD  $IN.pkt_delay_avg=350
#$CMD  $IN.pkt_send_num=1
