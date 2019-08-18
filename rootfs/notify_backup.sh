#!/bin/bash
### notified when switch to L7 master ###

VRID_L4=$1
VRID_L7=$2
L7VIP=$3
IFACE=$4
INGRESS_HTTPPORT=$5
INGRESS_HTTPSPORT=$6
echo "Switch to backup"
/routing.sh BACKUP $VRID_L4 $L7VIP $IFACE $INGRESS_HTTPPORT $INGRESS_HTTPSPORT
#/ipvsadm_daemon_backup.sh ${VRID_L4} ${IFACE} 2>&1 >> /var/log/keepalived-notify_${VRID_L4}.log

