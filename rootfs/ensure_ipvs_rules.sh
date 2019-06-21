#!/bin/bash

detectIpvsState(){
    
    L7VIP=$1
    L7VIPHttpPort=$2
    if [ ! -n "$L7VIP" ] || [ ! -n "$L7VIPHttpPort" ]; then
        echo "`date` $_SCRIPT_FILENAME_ $$ : $1 $2 : Error: invalid arguments. abort "
        exit 0
    fi

    _HEALTHY_IPVS_CONFIG_='$L7VIP:$L7VIPHttpPort'

    state=$(cat /var/run/keepalived.state)
    if [ -n "$state" ] && ( [ "$state" == "MASTER" ] || [ "$state" == "BACKUP" ]  ) ; then # not handle FAULT state, leave it to k8s health check
        # now keepalived is ready
            
        # check if ipvsadm -ln is cleared by kube-proxy or user
        result=`ipvsadm -ln | grep "${_HEALTHY_IPVS_CONFIG_}" | wc -l`
        if [ -n "$result" ] && (( result == 0 )) ; then
            echo " `date` $_SCRIPT_FILENAME_ $$ : $1 $2 failed to detect VIP rule for IPVS , return Unhealthy"
            exit -1
        fi
    fi
}


detectIpvsState $@
