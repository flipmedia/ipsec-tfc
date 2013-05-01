#!/bin/bash

file=$(mktemp)

cat > $file <<CutHere

flow esp from 192.168.1.0/24 to 192.168.2.0/24 peer 10.0.1.2

esp from 10.0.1.1 to 10.0.1.2 spi 0x100:0x200 \\
		auth hmac-sha1 enc aes \\
		authkey 0x657375636572756168746e656974616369746e6f:0x657375636572756168746e656974616369746e6f \\
		enckey 0x6573756365726e657263707969746e6f:0x6573756365726e657263707969746e6f

CutHere

ipsecctl -f $file

rm $file
