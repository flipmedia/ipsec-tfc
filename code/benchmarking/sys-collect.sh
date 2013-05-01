#!/bin/bash

## Collect measurements depending on host in testbed
## Assumed testbed layout: cli1--tfc1==mitm==tfc2--cli2
#
# Measurements:
# - inner/outer throughput
# - inner/outer pkt rate
# - inner/outer error rate
# - gateway CPU loads

ROOT="/root/IPsecCovertChannel/code/benchmarking"
source $ROOT/config.sh

# find the logging data dir of session $1
for LOG in /tmp/sys-trace*; do
	[ "$(cat $LOG/session)" = "$1" ] && break
done

if [ "$(cat $LOG/session)" != "$1" ]; then
	echo "Error: No such directory, exit."
	exit -1
fi

# collect and output measurements from $LOG
case $HOSTNAME in
	cli1)
		#kill $(cat $LOG/tasks.pid)
		if_drops eth1 > $LOG/drops2
		diff_drops $LOG/drops1 $LOG/drops2
		#echo
		#cat $LOG/bwmon
		rm -rf $LOG
		;;
	cli2)
		kill $(cat $LOG/tasks.pid)
		if_drops eth0 > $LOG/drops2
		diff_drops $LOG/drops1 $LOG/drops2
		echo
		cat $LOG/bwmon
		rm -rf $LOG
		;;
	tfc1)
		if_drops eth0 > $LOG/drops2
		diff_drops $LOG/drops1 $LOG/drops2
		rm -rf $LOG
		;;
	tfc2)
		if_drops eth0 > $LOG/drops2
		diff_drops $LOG/drops1 $LOG/drops2
		rm -rf $LOG
		;;
	mitm)
		kill $(cat $LOG/tasks.pid)
		if_drops eth0 > $LOG/drops2
		diff_drops $LOG/drops1 $LOG/drops2
		cat $LOG/bwmon
		rm -rf $LOG
		;;
	*)
		echo
		echo "Unknown host, pls reconfigure $0."
		exit
esac

echo $LOG
