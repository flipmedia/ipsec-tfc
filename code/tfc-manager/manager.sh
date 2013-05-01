#!/bin/bash

#killall tcpsvd
#killall netcat
#rsysctl="./rsysctl.sh"
killall token-secure
#port=1033
interval=200
#socket="fifo"

if [ $HOSTNAME = tfc1 ]; then
	echo launching for TFC1
	self=10.0.1.1
	peer=10.0.1.2
	tfc_dir="10-0-1-2:2"
	#LAN_filter="ip src net 192.168.1.0/24 and ip dst net 192.168.2.0/24"
	LAN_filter="ip dst net 192.168.2.0/24"
	./tfc-config.sh || exit
	./token-secure "$interval" /dev/null "$tfc_dir" eth1 "$LAN_filter" $1
else
	echo launching for TFC2
	self=10.0.1.2
	peer=10.0.1.1
	tfc_dir="10-0-1-1:2"
	#LAN_filter="ip src net 192.168.2.0/24 and ip dst net 192.168.1.0/24"
	LAN_filter="ip src net 192.168.2.0/24"
	./tfc-config.sh peer || exit
	./token-secure "$interval" /dev/null "$tfc_dir" eth0 "$LAN_filter" $1
fi
