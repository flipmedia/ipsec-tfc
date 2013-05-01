#!/bin/bash -e

## TFC performance tests
#
# leech  - repeated downloads with periods of silence
# web    - mixed web traffic and downloads
# webamp - mixed web traffic with amplified mgr reaction
###

TYPE=$1 # which scenario to run
SYNC=$2 # sync time/svn?

if [ "A$SYNC" = "A" ]; then
	./all-sync.sh
	./all-clean.sh
fi

. config.sh

###
## Initialize testbed and measurements
###
mkdir -p $LOG
$SYS_state > $LOG/status
TARGET=$(gettarget)

###
## Actual traffic tests
###

SESSION=$RANDOM
echo "Test $TEST, sessionID $SESSION"

# re-init manager
HOSTS="$GATEWAYS"
multissh "$IPSEC_init mgrTFC" && echo "IPsec/TFC for $TYPE"

## initialize measurements
HOSTS="$GATEWAYS $MITM $CLIENTS"
multissh "$SYS_trace $SESSION"

case $TYPE in
	"leech")
		TESTS="TCP_STREAM TCP_STREAM TCP_STREAM TCP_STREAM TCP_STREAM"
		LEN=10
		for TEST in $TESTS; do
			netperf -D 2,m -H $TARGET -t $TEST -l $LEN -i $NUM 
			sleep 10
		done |tee $LOG/${TYPE}_${LEN}_${NUM}
		;;
	"web")
		;&
	webamp_[0-9]*)
		shift; shift;
		out=$(ssh $TARGET "tsung -f $ROOT/benchmarking/tsung-benchmark.xml -w 4  start")
		echo "$out" |tee -a $LOG/status
		;;
	*)
		echo "Unknown benchmark $TYPE. Try one of leech, web, webrt. Exit."
		;;
esac

## collect measurements
HOSTS="$GATEWAYS $MITM $CLIENTS"
sleep 30 # wait for TFC to recover to end of simulation
for HOST in $HOSTS; do
	ssh $HOST $SYS_collect $SESSION > $LOG/${TYPE}_${HOST}
done
