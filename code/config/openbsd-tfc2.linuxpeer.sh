#!/bin/bash

PATH=/usr/local/sbin:$PATH

LAN1=192.168.1.0/24
GW1=10.0.1.1

LAN2=192.168.2.0/24
GW2=10.0.1.2


ip xfrm policy deleteall
ip xfrm state deleteall

rmmod tfc || echo "Unable to unload TFC"
modprobe tfc ipd_in_enable=1 ipd_out_enable=1

## This will add IPsec SP pair
ip xfrm policy add dir out src $LAN2 dst $LAN1 \
  tmpl src $GW2 dst $GW1 proto "esp" mode tunnel

ip xfrm policy add dir fwd src $LAN1 dst $LAN2 \
  tmpl src $GW1 dst $GW2 proto "esp" mode tunnel

ip xfrm policy add dir in src $LAN1 dst $LAN2 \
  tmpl src $GW1 dst $GW2 proto "esp" mode tunnel
  

## This will add IPsec SA pair for ESP protocol
ip xfrm state add src $GW1 dst $GW2 \
  spi 0x100 proto esp mode tunnel \
  auth "hmac(sha1)" 0x657375636572756168746e656974616369746e6f \
  enc "cbc(aes)" 0x6573756365726e657263707969746e6f \
	replay-window 32 \
  flag noecn fix-ds 

ip xfrm state add src $GW2 dst $GW1 \
  spi 0x200 proto esp mode tunnel \
  auth "hmac(sha1)" 0x657375636572756168746e656974616369746e6f \
  enc "cbc(aes)" 0x6573756365726e657263707969746e6f \
	replay-window 32 \
  flag noecn fix-ds 

## This will add IPsec SA pair for TFC protocol
#ip xfrm state add src $GW1 dst $GW2 proto "tfc" spi 0x03 mode tunnel
#ip xfrm state add src $GW2 dst $GW1 proto "tfc" spi 0x04 mode tunnel flag outbound
