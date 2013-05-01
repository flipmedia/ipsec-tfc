#!/bin/bash

if [ "A$ESP_SPI" = "A" -o "A$IP" = "A" ]
then
	echo "ESP parameters not specified, using defaults"
	ESP_SPI=1
	IP=`which ip`
fi


## IPsec policy for forwarding through tfc/esp tunnel
#
$IP xfrm policy add dir out src $LAN1 dst $LAN2 \
  tmpl src $GW1 dst $GW2 proto "esp" mode tunnel

$IP xfrm policy add dir fwd src $LAN2 dst $LAN1 \
  tmpl src $GW2 dst $GW1 proto "esp" mode tunnel

$IP xfrm policy add dir in src $LAN2 dst $LAN1 \
  tmpl src $GW2 dst $GW1 proto "esp" mode tunnel
  

## IPsec states (SA) for ESP tunnel using AES in GCM mode
# Flags: decap-dscp nopmtudisc noecn wildrecv af_unspec
#
$IP xfrm state add src $GW1 dst $GW2 spi $ESP_SPI proto esp mode tunnel \
	aead "rfc4106(gcm(aes))" "12345678901234567890" 128 replay-window 32 flag noecn fix-ds
$IP xfrm state add src $GW2 dst $GW1 spi $ESP_SPI proto esp mode tunnel \
	aead "rfc4106(gcm(aes))" "12345678901234567890" 128 replay-window 32 flag noecn fix-ds
