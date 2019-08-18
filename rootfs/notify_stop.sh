#!/bin/bash

VRID=$1

/routing.sh unset $VRID
ipvsadm --stop-daemon master
ipvsadm --stop-daemon backup


