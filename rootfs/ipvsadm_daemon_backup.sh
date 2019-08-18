#!/bin/bash +e

VRID=$1
IFACE=$2

ipvsadm --stop-daemon master
ipvsadm --stop-daemon backup 
ipvsadm --start-daemon backup --mcast-interface=${IFACE} --syncid ${VRID}

