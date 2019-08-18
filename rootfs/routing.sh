#!/bin/bash

#------
#author: Lan Weizhou
#-------
Operation=$1
LB_ID=$2
VIP=$3
LOCAL_IF=$4     # NIC interface  like ens192
RShttpPort=$5    # real server http port
RShttpSPort=$6


INGRESS_PORT=" $RShttpPort:$RShttpSPort "

#INGRESS_PORT=" XXX_RS_HTTP_PORT_XXX:XXX_RS_HTTPS_PORT_XXX "
#------




#MARK="0xd05"
#ROUTING_TABLE_NUM=100
vrid=$LB_ID
MARK=$((2000+$vrid))
MARK="0x"$(printf "%x" $MARK)
ROUTING_TABLE_NUM=$vrid

LOG_FILE="/var/log/keepalived-notify_${LB_ID}.log"

COMMENT_HTTP="http : ingress routing rule for LB($LB_ID) ipvs NAT mode"
COMMENT_HTTPS="https : ingress routing rule for LB($LB_ID) ipvs NAT mode"

iptables="iptables-legacy"


_SCRIPT_FILENAME_=`basename $0`
#_LOCK_FILE_='/etc/keepalived/_lock'
_STATUS_FLAG_FILE='/etc/keepalived/_keepalived_status_'


usage(){
    echo "$_SCRIPT_FILENAME_ $$:  <backup|master/set> <LB_ID(1-255)> <L7_VIP> <NIC_Interface> <L7_RS_Http_Port> <L7_RS_Https_Port>" 
    echo "$_SCRIPT_FILENAME_ $$:  <unset> <LB_ID(1-255)>" 
}


############ main ################
if [ "$Operation" != "unset" ] && [ $# -ne 6 ]; then
    usage
	exit 1
fi
if [ "$Operation" == "unset" ] && [ $# -ne 2 ]; then
   usage
   exit 1
fi

clog(){
	echo "`date` $_SCRIPT_FILENAME_ $$: $Operation $@" | tee -a ${LOG_FILE}

}

unset_routing(){
	clog 'function: unset_routing'

    while true ; do
      LINE=` $iptables -t mangle -nxvL OUTPUT --line | grep "$COMMENT_HTTP" | awk '{print $1}' | head -1`
      if [ -n "$LINE" ] && expr "$LINE" + 1 &> /dev/null ;then
          clog "unset http rule : found rule number $LINE"
          $iptables -t mangle -D OUTPUT $LINE
      else
          break
      fi
    done

    while true ; do
      LINE=` $iptables -t mangle -nxvL OUTPUT --line | grep "$COMMENT_HTTPS" | awk '{print $1}' | head -1`
      if [ -n "$LINE" ] && expr "$LINE" + 1 &> /dev/null ;then
          clog "unset http rule : found rule number $LINE"
          $iptables -t mangle -D OUTPUT $LINE
      else
          break
      fi
    done


	LINE=`ip rule | grep "fwmark $MARK lookup" | awk -F: '{ if (NR==1) print $1}'`
	if [ -n "$LINE" ] && egrep '^[[:digit:]]+$' <<< "$LINE" >/dev/null 2>&1 ;then
		clog "unset ip rule: : found rule number $LINE "
		ip rule delete prio $LINE
	fi

	INFO=`ip route show table $ROUTING_TABLE_NUM`
	if [ -n "$INFO" ];then
        clog "unset ip route"
        ip route delete default table $ROUTING_TABLE_NUM
	fi

    ip route flush cache
    clog 'done'
}

set_routing(){
	clog  'function: set_routing'

    for port in ${INGRESS_PORT} ; do
        https_port=${port#*:}
        http_port=${port%:*}

        clog "set rule for http $http_port and https $https_port"
        $iptables -t mangle -A OUTPUT -p tcp --sport $http_port -j MARK --set-mark $MARK -m comment --comment "$COMMENT_HTTP"
        $iptables -t mangle -A OUTPUT -p tcp --sport $https_port -j MARK --set-mark $MARK -m comment --comment "$COMMENT_HTTPS"
    done

	INFO=` ip rule | grep "fwmark $MARK lookup"  `	
	if [ -z "$INFO" ];then
        clog 'set ip rule'
        ip rule add fwmark $MARK table $ROUTING_TABLE_NUM
	fi

	INFO=` ip route show table  $ROUTING_TABLE_NUM   `	
	if [ -z "$INFO" ];then
        clog 'set ip route'
        ip route add default via $VIP dev $LOCAL_IF table $ROUTING_TABLE_NUM
	fi

    ip route flush cache
    clog  'done'
}
#################################################
# SPDX-License-Identifier: MIT

## Copyright (C) 2009 Przemyslaw Pawelczyk <przemoc@gmail.com>
##
## This script is licensed under the terms of the MIT license.
## https://opensource.org/licenses/MIT
#
# Lockable script boilerplate

### HEADER ###

LOCKFILE="/var/lock/`basename $0`"
LOCKFD=99

# PRIVATE
_lock()             { flock -$1 $LOCKFD; }
_no_more_locking()  { _lock u; _lock xn && rm -f $LOCKFILE; }
_prepare_locking()  { eval "exec $LOCKFD>\"$LOCKFILE\""; trap _no_more_locking EXIT; }

# ON START
_prepare_locking

# PUBLIC
exlock_now()        { _lock xn; }  # obtain an exclusive lock immediately or fail
exlock()            { _lock x; }   # obtain an exclusive lock
shlock()            { _lock s; }   # obtain a shared lock
unlock()            { _lock u; }   # drop a lock

# Remember! Lock file is removed when one of the scripts exits and it is
#           the only script holding the lock or lock is not acquired at all.

################################################################


clog "---------begin---($VIP)--------"
exlock
clog "---------get-the-lock-----------"
if [ x"$Operation" == x"BACKUP" ] ; then
    clog  "keepalived changed to backup"
    unset_routing
    set_routing
    echo "$Operation" > $_STATUS_FLAG_FILE
elif [  x"$Operation" == x"set" ] ; then
    clog  "set up routing rules"
    unset_routing
    set_routing
    echo "$Operation" > $_STATUS_FLAG_FILE
elif [  x"$Operation" == x"unset" ] ; then
    clog  "unset up routing rules"
    unset_routing    
    echo "$Operation" > $_STATUS_FLAG_FILE
elif [  x"$Operation" == x"MASTER" ] ; then
    clog  "keepalived changed to master"
    unset_routing
    echo "$Operation" > $_STATUS_FLAG_FILE
elif [ x"$Operation" == x"FAULT" ] ; then 
    clog  "keepalived changed to fault"
    unset_routing
    echo "$Operation" > $_STATUS_FLAG_FILE
else
    clog  "bad status =$Operation= "
fi


clog "---------done--($VIP)---------"
exit 0
