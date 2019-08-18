#!/bin/bash
CONFFILE="/etc/keepalived/keepalived.conf"
VIPS=$(cat $CONFFILE|grep dev |awk '{print $1}' ) # line is like         10.6.100.99 dev ens192
VRIDS=$(cat $CONFFILE|grep virtual_router_id|awk '{print $2}') #line is like       virtual_router_id 4
log(){
    echo "$(date) Waiting keepalived cleanup: remainding :$1" 
}
set +e
check_output_blank(){
    cmd="$1"
    echo "    $(date) Doing " "$cmd"
    ret=$(eval $cmd)    #shell command
    if [ $? -ne 0 ]; then
        return 0 #grep failure, means output is blank
    fi
    if [ "$ret" != "" ]; then
        log "$ret"
	return 1 # False
    else
	return 0 # true
    fi

}
check_commands=()
iptl="iptables-legacy"
for vrid in ${VRIDS[@]};do
   echo "vrid=$vrid"
   check_commands+=(
    "ip rule | grep \"from all fwmark\"|grep \"lookup $vrid\""
    "ip route show table $vrid"
    "$iptl -t mangle -nxvL OUTPUT |grep \"ingress routing rule for LB($vrid) ipvs NAT mode\""
    "$iptl -t nat -nxvL|grep DCE_L4_SNAT_CHAIN_$vrid"
    "$iptl -t nat -nxvL|grep DCE_L7_EXCEPTION_RULES_$vrid"
    "$iptl -t nat -nxvL PREROUTING |grep DCE_L4_IGNORE_KUBE_PROXY_FOR_VIP_RULES_$vrid"
   )
done
for vip in ${VIPS[@]};do
    echo "vip=$vip"
    #check_commands+=("ipvsadm -Ln |grep $vip")
    #check_commands+=("ip a |grep $vip")
done

echo "===$(date)==Clean up Check for VIPS=${VIPS[@]} , vrid = ${VRIDS[@]}"
for ((i = 0; i < ${#check_commands[@]}; i++)); do
    cmd="${check_commands[$i]}"
    check_output_blank "$cmd"
done



