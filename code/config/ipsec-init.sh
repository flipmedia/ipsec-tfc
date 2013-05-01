#!/bin/bash -e

###
## Base Configuration
###

export PATH=/usr/local/sbin:$(dirname $0):$PATH
export IP=`which ip`
export ESP_SPI=1
export TFC_SPI=2


export LAN1=192.168.1.0/24
export LAN2=192.168.2.0/24
export GW1=10.0.1.1
export GW2=10.0.1.2

# Pipe all traffic through tunnel (GW1 is Internet gw)
LAN1=0.0.0.0/0

###
## Operation Mode
###

# Usage: ./tfc-setup.sh [rawTFC,noTFC,loTFC,hiTFC,mgdTFC]
#
# "noTFC"  -> no TFC at all
# "rawTFC" -> no normalization in TFC (measure raw implementation overhead)
# "loTFC" -> fully padded channel with small packets (-> high rate)
# "hiTFC" -> fully padded channel with large packets (-> low rate)
# "mgrTFC" -> launch userspace TFC manager (adapt to LAN usage)
export HOST=$HOSTNAME
export MODE=$1

###
## Tunnel Endpoint detection
###

case $HOST in
	"tfc1")
		;;
	"tfc2")
		# swap endpoints
		tmp="$LAN1"
		export LAN1="$LAN2"
		export LAN2="$tmp"
		tmp="$GW1"
		export GW1="$GW2"
		export GW2="$tmp"
		;;
	*)
		echo "Unknown endpoint \"$HOST\"."
		echo "Please define which end of tunnel we are (start/end)."
		echo
		exit
		;;
esac


###
## (Re-)Initialize IPsec
###

## Reset/check IPsec/TFC
ipsec-reset-all.sh || echo "Trying anyway...?!"

## Initialize ESP/TFC tunnel
if [ "$MODE" = "noTFC" ]
then
	ipsec-esp.sh
else
	ipsec-tfc-esp.sh $MODE
fi
