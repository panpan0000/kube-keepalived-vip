#!/bin/bash

$VRID=$1
$L7VIP=$2
$IFACE=$3
$INGRESS_HTTPPORT=$4
$INGRESS_HTTPSPORT=$5
echo "Switch to backup"
/routing.sh BACKUP $VRID $L7VIP $IFACE $INGRESS_HTTPPORT $INGRESS_HTTPSPORT

ipvsadm --stop-daemon master
ipvsadm --start-daemon backup --mcast-interface=${IFACE} --syncid ${VRID}

