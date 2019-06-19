#!/bin/bash

#------
#author: Lan Weizhou
#-------

Operation=$1
VIP=$2
LOCAL_IF=$3      # NIC interface  like ens192
RShttpPort=$4    # real server http port
RShttpSPort=$5

INGRESS_PORT=" $RShttpPort:$RShttpSPort "

#INGRESS_PORT=" XXX_RS_HTTP_PORT_XXX:XXX_RS_HTTPS_PORT_XXX "
#------

LOG_FILE="/etc/keepalived/log"

MARK="0xd05"
ROUTING_TABLE_NUM=100

COMMENT_HTTP="http : ingress routing rule for ipvs NAT mode"
COMMENT_HTTPS="https : ingress routing rule for ipvs NAT mode"



_SCRIPT_FILENAME_=`basename $0`
#_LOCK_FILE_='/etc/keepalived/_lock'
_STATUS_FLAG_FILE='/etc/keepalived/_keepalived_status_'


usage(){
    echo "$_SCRIPT_FILENAME_ $$:  <backup|master/unset/set> <L7_VIP> <NIC_Interface> <L7_RS_Http_Port> <L7_RS_Https_Port>" 
}


############ main ################
if [ $# -ne 5 ]; then
    usage
	exit 1
fi


clog(){
	echo "`date` $_SCRIPT_FILENAME_ $$: $Operation" | tee -a ${LOG_FILE}

}

unset_routing(){
	clog 'function: unset_routing'

    while true ; do
      LINE=` iptables -t mangle -nxvL OUTPUT --line | grep "$COMMENT_HTTP" | awk '{print $Operation}' | head -1`
      if [ -n "$LINE" ] && expr "$LINE" + 1 &> /dev/null ;then
          clog "unset http rule : found rule number $LINE"
          iptables -t mangle -D OUTPUT $LINE
      else
          break
      fi
    done

    while true ; do
      LINE=` iptables -t mangle -nxvL OUTPUT --line | grep "$COMMENT_HTTPS" | awk '{print $Operation}' | head -1`
      if [ -n "$LINE" ] && expr "$LINE" + 1 &> /dev/null ;then
          clog "unset http rule : found rule number $LINE"
          iptables -t mangle -D OUTPUT $LINE
      else
          break
      fi
    done


	LINE=`ip rule | grep "fwmark $MARK lookup" | awk -F: '{ if (NR==1) print $Operation}'`
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
        iptables -t mangle -A OUTPUT -p tcp --sport $http_port -j MARK --set-mark $MARK -m comment --comment "$COMMENT_HTTP"
        iptables -t mangle -A OUTPUT -p tcp --sport $https_port -j MARK --set-mark $MARK -m comment --comment "$COMMENT_HTTPS"
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



trap "clog 'got kill signal , bye' && exit 0 " 1


clog "---------begin-----------"

if [ x"$Operation" == x"backup" ] ; then
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
elif [  x"$Operation" == x"master" ] ; then
    clog  "keepalived changed to master"
    unset_routing
    echo "$Operation" > $_STATUS_FLAG_FILE
elif [ x"$Operation" == x"fault" ] ; then 
    clog  "keepalived changed to fault"
    unset_routing
    echo "$Operation" > $_STATUS_FLAG_FILE
else
    clog  "bad status =$Operation= "
fi


clog "---------done-----------"
exit 0
