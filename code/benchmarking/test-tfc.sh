#!/bin/bash -e

## TFC performance tests
#
# TFC500, TFC800, TFC1422 -> fully padded channel at 100Mbit/s with size N
# mgrTFC -> launch userspace TFC manager (adapt to LAN usage)
###

TYPE=$1 # which test
SYNC=$2 # sync time/svn?

if [ "$TYPE" != "TFC500" -a "$TYPE" != "TFC800" -a "$TYPE" != "TFC1422" -a "$TYPE" != "mgrTFC" ]; then
	echo "Unknown benchmark $TYPE. Try one of loTFC, hiTFC, mgrTFC. Exit."
	exit -1
fi

if [ "A$SYNC" = "A" ]; then
	./all-sync.sh
	./all-clean.sh
fi

. config.sh


###
## Initialize testbed and measurements
###
HOSTS="$GATEWAYS"
multissh "$IPSEC_init $TYPE" && echo "IPsec/TFC for $TYPE"

mkdir -p $LOG
$SYS_state > $LOG/status
TARGET=$(gettarget)

###
## Actual traffic tests
###
for TEST in $TESTS; do
	SESSION=$RANDOM
	echo "Test $TEST, sessionID $SESSION"

	## initialize measurements
	HOSTS="$GATEWAYS $MITM $CLIENTS"
	multissh "$SYS_trace $SESSION"

	## run benchmark
	netperf -D 2,m -H $TARGET -t $TEST -l $LEN -i $NUM |tee $LOG/${TEST}_${LEN}_${NUM}

	## collect measurements
	HOSTS="$GATEWAYS $MITM $CLIENTS"
	for HOST in $HOSTS; do
		ssh $HOST $SYS_collect $SESSION > $LOG/${TEST}_${HOST}
	done

	## wait for token recovery?!
	#sleep 60
done

