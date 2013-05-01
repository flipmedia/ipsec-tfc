#!/bin/bash -e

###
## Sync systems for benchmark
###

. config.sh

## Sync clocks if they arent..
HOSTS="$GATEWAYS $MITM $CLIENTS"
dates=$(multissh "date +%s"|awk '{print $2}')
echo -e "Times:\n$dates"
# if [ "$(echo "$dates" |uniq -c|tail -1|awk '{print $1}')" -ne 5 ]; then
# 	multissh ntpdate-debian
# fi

## Sync SVN
HOSTS="$GATEWAYS $MITM cli2"
multissh "cd ~/IPsecCovertChannel; git xpull"
