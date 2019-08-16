#!/bin/bash

list_par=(
"ulimit -n 65535"
"echo 262144 > /sys/module/nf_conntrack/parameters/hashsize"
"sysctl -w net.netfilter.nf_conntrack_max=1048576"
"sysctl -w fs.file-max=1048576"
"sysctl -w fs.nr_open=1000000"
"sysctl -w net.ipv4.ip_local_port_range='1024 65535'"
#tcp队列
"sysctl -w net.ipv4.tcp_syncookies=1"
"sysctl -w net.ipv4.tcp_synack_retries=1"
"sysctl -w net.ipv4.tcp_max_syn_backlog=8196"
"sysctl -w net.core.somaxconn=4096"
#容器重启下
"sysctl -w net.core.netdev_max_backlog=65536"
"sysctl -w net.ipv4.tcp_abort_on_overflow=0"
#tcp行为
"sysctl -w net.ipv4.tcp_timestamps=1"
"sysctl -w net.ipv4.tcp_tw_recycle=0"
"sysctl -w net.ipv4.tcp_tw_reuse=1"
"sysctl -w net.ipv4.tcp_slow_start_after_idle=0"
"sysctl -w net.ipv4.tcp_rfc1337=1"
"sysctl -w net.ipv4.tcp_window_scaling=1"
"sysctl -w net.ipv4.tcp_sack=0"
"sysctl -w net.ipv4.tcp_fack=0"
"sysctl -w net.ipv4.tcp_congestion_control=htcp"
"sysctl -w net.ipv4.tcp_low_latency=0"
"sysctl -w net.ipv4.tcp_frto=2"
"sysctl -w net.ipv4.tcp_adv_win_scale=1"
#tcp内存
"sysctl -w net.core.rmem_max=16777216"
"sysctl -w net.core.wmem_max=16777216"
"sysctl -w net.ipv4.tcp_rmem='4096 4194304 16777216'"
"sysctl -w net.ipv4.tcp_wmem='4096 4194304 16777216'"
"sysctl -w net.core.wmem_default=4194304"
"sysctl -w net.core.rmem_default=4194304"
"sysctl -w net.core.optmem_max=102400"
"sysctl -w net.ipv4.tcp_moderate_rcvbuf=1"
#
"sysctl -w net.ipv4.tcp_keepalive_intvl=10"
"sysctl -w net.ipv4.tcp_keepalive_probes=2"
"sysctl -w net.ipv4.tcp_keepalive_time=300"
"sysctl -w net.ipv4.tcp_max_orphans=132144"
"sysctl -w net.ipv4.tcp_orphan_retries=2"
"sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=600"
"sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=30"
"sysctl -w net.netfilter.nf_conntrack_tcp_timeout_fin_wait=30"
"sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close_wait=30"
"sysctl -w net.ipv4.tcp_fin_timeout=30"
"sysctl -w net.ipv4.tcp_syn_retries=2"
"sysctl -w net.ipv4.tcp_max_tw_buckets=65535"
)

COMMENT="#optimize system network parameters"
_FILEPATH_RC_LOCAL_="/etc/rc.d/rc.local"

unset_all()
{
        sed -i '/'"${COMMENT}"'/ d' ${_FILEPATH_RC_LOCAL_}
}


set_all()
{
    if [ ! -x "$_FILEPATH_RC_LOCAL_" ];then
        chmod +x ${_FILEPATH_RC_LOCAL_}
    fi

    OLD="$IFS"
    IFS=$'\n'
    for item in ${list_par[@]};do
        echo "$item  $COMMENT" >> "${_FILEPATH_RC_LOCAL_}"
        eval $item
    done
    IFS="$OLD"
    

  for item in `sysctl -a 2> /dev/null | grep '\.rp_filter' | awk '{print $1}'` ; do
      tmp="sysctl -w ${item}=2 #optimize network"
      if ! grep "$tmp" "${_FILEPATH_RC_LOCAL_}" &> /dev/null ; then
          echo "$tmp" >>  "${_FILEPATH_RC_LOCAL_}"
      fi
      eval $tmp
  done
}



if [  x"$1" == x"set" ] ; then
    echo  "optimizing"
    unset_all
    set_all
elif [  x"$1" == x"unset" ] ; then
    echo  "unset optimization"
    unset_all
else
    echo  "optimizing"
    unset_all
    set_all
fi

echo "succeeded!"




