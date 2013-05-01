#!/bin/bash -e

## Initialize IPsec ESP/TFC tunnel (IPsec SA bundle)
## Network configuration is part of $env. MODE in $1 may be one of:
#
# "rawTFC" -> no normalization in TFC (measure raw implementation overhead)
# "loTFC" -> fully padded channel with small packets (-> high rate)
# "hiTFC" -> fully padded channel with large packets (-> low rate)
# "mgrTFC" -> launch userspace TFC manager (adapt to LAN usage)
##

ROOT="/root/IPsecCovertChannel/code/"
MODE="$1"

if [ "A$ESP_SPI" = "A" -o "A$IP" = "A" -o "A$TFC_SPI" = "A" ]
then
	echo "TFC/ESP parameters not specified, using defaults"
	ESP_SPI=1
	TFC_SPI=2
	IP=`which ip`
fi

## Double-check TFC, we cannot re-initialize if already loaded!!
STATE=$(sed -e s/.*enabled// /proc/sys/net/ipv4/tfc/*/ipd_enabled|tr -d '\n')

if $(lsmod|grep -q ^"tfc "); then
	if [ "$MODE" = "rawTFC" ]; then
		if [ "$STATE" -ne 0 ]; then
			echo "TFC already loaded in non-raw mode, bailing out."
			exit
		fi
	else # non-raw TFC loaded -> just reload TFC config
		killall token-secure || true
		export "TFC_CTL_out=${GW2//\./-}:${TFC_SPI}"
		export "TFC_CTL_in=${GW2//\./-}:${TFC_SPI}"
		[ "$MODE" = "rawTFC" ]  && . tfc-raw.conf
		[ "$MODE" = "TFC500" ]  && . tfc-500.conf
		[ "$MODE" = "TFC800" ]  && . tfc-800.conf
		[ "$MODE" = "TFC1422" ] && . tfc-1422.conf
		[ "$MODE" = "mgrTFC" ]  && ( cd $ROOT/tfc-manager/; nohup ./manager.sh > /dev/null & )
		exit
	fi
else
	## Use full TFC?
	if [ "$MODE" = "rawTFC" ]; then
		modprobe tfc ipd_in_enable=0 ipd_out_enable=0
	else
		modprobe tfc ipd_in_enable=0 ipd_out_enable=1
	fi
fi

## IPsec policy for forwarding through tfc/esp tunnel
$IP xfrm policy add dir out src $LAN1 dst $LAN2 \
  tmpl src $GW1 dst $GW2 proto "tfc" mode tunnel \
  tmpl src $GW1 dst $GW2 proto "esp" mode tunnel

$IP xfrm policy add dir fwd src $LAN2 dst $LAN1 \
  tmpl src $GW2 dst $GW1 proto "tfc" mode tunnel \
  tmpl src $GW2 dst $GW1 proto "esp" mode tunnel

$IP xfrm policy add dir in src $LAN2 dst $LAN1 \
  tmpl src $GW2 dst $GW1 proto "tfc" mode tunnel \
  tmpl src $GW2 dst $GW1 proto "esp" mode tunnel
  

## IPsec states (SA) for ESP tunnel using AES in GCM mode
#
# Flags: decap-dscp nopmtudisc noecn wildrecv af_unspec
$IP xfrm state add src $GW1 dst $GW2 spi $ESP_SPI proto esp mode tunnel \
	aead "rfc4106(gcm(aes))" "12345678901234567890" 128 replay-window 32 flag noecn fix-ds
$IP xfrm state add src $GW2 dst $GW1 spi $ESP_SPI proto esp mode tunnel \
	aead "rfc4106(gcm(aes))" "12345678901234567890" 128 replay-window 32 flag noecn fix-ds

## IPsec states (SAs) for TFC tunnel (configured by sysctl)
$IP xfrm state add src $GW1 dst $GW2 proto "tfc" spi $TFC_SPI mode tunnel flag outbound
$IP xfrm state add src $GW2 dst $GW1 proto "tfc" spi $TFC_SPI mode tunnel


export "TFC_CTL_out=${GW2//\./-}:${TFC_SPI}"
export "TFC_CTL_in=${GW2//\./-}:${TFC_SPI}"
#set |grep ^TFC_CTL_


[ "$MODE" = "rawTFC" ]  && . tfc-raw.conf
[ "$MODE" = "TFC500" ]  && . tfc-500.conf
[ "$MODE" = "TFC800" ]  && . tfc-800.conf
[ "$MODE" = "TFC1422" ] && . tfc-1422.conf
[ "$MODE" = "mgrTFC" ]  && ( cd $ROOT/tfc-manager/; nohup ./manager.sh > /dev/null & )
