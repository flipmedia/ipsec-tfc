#!/bin/bash

## Do measurements depending on host in testbed
## Assumed testbed layout: cli1--tfc1==mitm==tfc2--cli2
#
# Measurements:
# - inner/outer throughput
# - inner/outer pkt rate
# - inner/outer error rate
# - gateway CPU loads

ROOT="/root/IPsecCovertChannel/code/benchmarking"
source $ROOT/config.sh

LOG=$(mktemp --tmpdir=/tmp -d sys-trace.XXXXX)
echo "$1" > $LOG/session

case $HOSTNAME in
	cli1)
		if_drops eth1 > $LOG/drops1
		#nohup $UTIL_bwmon eth0 'ip dst net 192.168.1.0/24 or ip dst net 192.168.2.0/24' > $LOG/bwmon &
		#echo "$!" > $LOG/tasks.pid
		;;
	cli2)
		if_drops eth0 > $LOG/drops1
		nohup $UTIL_bwmon eth0 'ip dst net 192.168.1.0/24 or ip dst net 192.168.2.0/24' > $LOG/bwmon &
		echo "$!" > $LOG/tasks.pid
		;;
	tfc1)
		if_drops eth0 > $LOG/drops1
		;;
	tfc2)
		if_drops eth0 > $LOG/drops1
		;;
	mitm)
		if_drops eth0 > $LOG/drops1
		nohup $UTIL_bwmon br0 'ip dst net 10.0.1.0/24 or ip dst net 192.168.1.0/24 or ip dst net 192.168.2.0/24' > $LOG/bwmon &
		echo "$!" > $LOG/tasks.pid
		;;
	*)
		echo
		echo "Unknown host, pls reconfigure $0."
		exit
esac

echo "saving to $LOG"
