#!/bin/bash +e

VRID=$1
IFACE=$2
ipvsadm --stop-daemon backup
ipvsadm --stop-daemon master 
ipvsadm --start-daemon master --mcast-interface=${IFACE} --syncid ${VRID} #use vrid as syncid

