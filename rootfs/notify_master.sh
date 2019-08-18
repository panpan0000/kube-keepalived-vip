#!/bin/bash

$VRID=$1
$L7VIP=$2
$IFACE=$3
$INGRESS_HTTPPORT=$4
$INGRESS_HTTPSPORT=$5
echo "Switch to master"
/routing.sh MASTER $VRID $L7VIP $IFACE $INGRESS_HTTPPORT $INGRESS_HTTPSPORT
ipvsadm --stop-daemon backup
ipvsadm --start-daemon master --mcast-interface=${IFACE} --syncid ${VRID} #use vrid as syncid

