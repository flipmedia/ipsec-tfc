#!/bin/bash

## Reset unclean host states, killing possibly left processes and logs
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
	rm -rvf $LOG
	echo 
done

which tsung && tsung stop

killall bw-mon || true
