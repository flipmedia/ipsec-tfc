#!/bin/bash -e

###
## Clean all temporary files on all hosts
###

ROOT="/root/IPsecCovertChannel/code/benchmarking"
. $ROOT/config.sh

HOSTS="$GATEWAYS $MITM $CLIENTS"
multissh $SYS_clean
	
echo "Setting MTU.."
ssh cli1 "ifconfig eth1 mtu 1412"
ssh cli2 "ifconfig eth0 mtu 1412"
