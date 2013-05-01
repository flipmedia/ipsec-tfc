#!/bin/bash -e

PATH=/usr/local/sbin:$PWD:$PATH
ROOT="/root/IPsecCovertChannel/code/"

DEST_DIR=../../data/
LEN=20
NUM=1
TESTS="TCP_STREAM TCP_MAERTS TCP_RR"

GATEWAYS="tfc1 tfc2"
CLIENTS="cli1 cli2"
MITM="mitm"

IPSEC_reset=$ROOT/config/ipsec-reset-all.sh
IPSEC_init=$ROOT/config/ipsec-init.sh
SYS_state=$ROOT/benchmarking/sys-state.sh
SYS_trace=$ROOT/benchmarking/sys-trace.sh
SYS_collect=$ROOT/benchmarking/sys-collect.sh
SYS_clean=$ROOT/benchmarking/sys-clean.sh
UTIL_bwmon=$ROOT/tools/bw-mon

## destination dir for measurement (uses $TYPE from calling script)
LOG=$DEST_DIR/$TYPE-$(date +%s)

function gettarget()
{
case $HOSTNAME in
	cli1)
		echo "cli2"
		;;
	cli2)
		echo "cli1"
		;;
	*)
		echo "Target unknown for measuring performance from here, check config.sh"
		exit
		;;
esac
}

function multissh()
{
	for HOST in $HOSTS; do
		echo -n "${HOST}: "
		ssh $HOST "$1"
	done
}

if_drops() {
	/sbin/ifconfig $1|grep dropped|sed s/.*dropped://|sed s/\ .*//
}


diff_drops() {
	echo "dropped rx/tx: $(( $(head -1 $2)-$(head -1 $1) ))/$(( $(tail -1 $2)-$(tail -1 $1) ))"
}
