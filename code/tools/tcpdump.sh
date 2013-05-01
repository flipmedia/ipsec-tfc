#!/bin/sh

# prints "timestamp length", one line per packet
tcpdump -ni eth0 'ip src 10.0.0.1 and esp'|awk '{print $1 $9}'
