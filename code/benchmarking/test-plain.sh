#!/bin/bash -e

###
## Raw network performance test
###

TYPE=$1 # which test
SYNC=$2 # sync time/svn?

if [ $TYPE != "raw" -a "$TYPE" != "esp" -a "$TYPE" != "tfc" ]; then
	echo "Unknown benchmark $TYPE. Try one of raw, esp, tfc. Exit."
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
[ "$TYPE" = "raw" ] && multissh $IPSEC_reset					&& echo "IPsec disabled"
[ "$TYPE" = "esp" ] && multissh "$IPSEC_init noTFC"		&& echo "IPsec ESP only"
[ "$TYPE" = "tfc" ] && multissh "$IPSEC_init rawTFC"	&& echo "IPsec bare TFC"

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

