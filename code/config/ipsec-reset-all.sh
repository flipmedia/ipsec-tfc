#!/bin/sh

IP=`which ip`


# if TFC is loaded and was used, we cannot do anything anyway and should not try to delete the SAs
if (lsmod|grep -q ^"tfc " ); then
	rmmod tfc || exit 1
fi

$IP xfrm policy deleteall
$IP xfrm state deleteall
