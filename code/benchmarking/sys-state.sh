#!/bin/bash

if [ -d .svn ]
then
	rev=$(svn info 2>/dev/null|grep Revision)
else
	rev=$(git svn info 2>/dev/null|grep Revision)
fi
[ ${rev#Revision:} -lt 0 ] && echo "Bad repository revision in sys-state.sh" && exit


echo "Test on $(date), Repository r${rev#R}"
uname -a
echo Load @$(date +%s): $(cat /proc/loadavg)
