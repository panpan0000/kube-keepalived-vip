#!/bin/bash

VRID_L4=$1
VRID_L7=$2

/routing.sh unset $VRID_L4
#/ipvsadm_daemon_stop.sh >> /var/log/keepalived-notify_${VRID_L4}.log

