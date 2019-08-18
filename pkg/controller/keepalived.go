/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"strconv"
	"syscall"
	"text/template"
	"time"

	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/util/iptables"
	k8sexec "k8s.io/utils/exec"
)

const (
	iptablesChain   = "KUBE-KEEPALIVED-VIP"
	keepalivedCfg   = "/etc/keepalived/keepalived.conf"
	haproxyCfg      = "/etc/haproxy/haproxy.cfg"
	keepalivedPid   = "/var/run/keepalived.pid"
	keepalivedState = "/var/run/keepalived.state"
	vrrpPid         = "/var/run/vrrp.pid"
)

var (
	keepalivedTmpl = "keepalived.tmpl"
	haproxyTmpl    = "haproxy.tmpl"
)

type epMetrics struct {
	EpIp   string
	EpPort int32
	Conns  int
	InPkts int
	OutPkts  int
	InBytes  int
	OutBytes int
	CPS    int
	InPPS  int
	OutPPS int
	InBPS  int
	OutBPS int
}
type vipInfo struct {
    MasterNodeName string
}

type metricsStruct struct{
    NodeName string
    VipsSum []vipSummary
    MetricsData []vipMetrics
}
type vipSummary struct {
    Vip string
    Conns int
    InPkts int
	OutPkts  int
	InBytes  int
	OutBytes int
	CPS    int
	InPPS  int
	OutPPS int
	InBPS  int
	OutBPS int
}
type vipMetrics struct {
	Protocol string
	Vip     string
	Port    int32
	Eps     []epMetrics
	Conns  int
	InPkts int
	OutPkts  int
	InBytes  int
	OutBytes int
	CPS    int
	InPPS  int
	OutPPS int
	InBPS  int
	OutBPS int

}

type keepalived struct {
	iface          string
	ip             string
	netmask        int
	priority       int
	nodes          []string
	neighbors      []string
	useUnicast     bool
	started        bool
	vips           []string
    l7vip          string
	keepalivedTmpl *template.Template
	haproxyTmpl    *template.Template
	cmd            *exec.Cmd
	ipt            iptables.Interface
	vrid           int
	proxyMode      bool
	notify         string
	releaseVips    bool
	snatChain      string
    snatExceptionKey string
    l7eps         []string
    IgnoreKubeProxyKey string
    previousL4Vips []string
}

// WriteCfg creates a new keepalived configuration file.
// In case of an error with the generation it returns the error
func (k *keepalived) WriteCfg(svcs []vip, settings globalSetting ) error {
	w, err := os.Create(keepalivedCfg)
	if err != nil {
		return err
	}
	defer w.Close()

	k.vips = getVIPs(svcs)
    k.l7vip = settings.L7VIP
	if settings.iface != "" {
	    k.iface = settings.iface
	}

	conf := make(map[string]interface{})
	conf["iptablesChain"] = iptablesChain
	conf["iface"] = k.iface
	conf["myIP"] = k.ip
	conf["netmask"] = k.netmask
	conf["svcs"] = svcs
	conf["vips"] = k.vips
	conf["nodes"] = k.neighbors
	conf["priority"] = k.priority
	conf["useUnicast"] = k.useUnicast
	conf["vrid"] = k.vrid
	conf["proxyMode"] = k.proxyMode
	conf["vipIsEmpty"] = len(k.vips) == 0
	conf["notify"] = k.notify
    conf["delay_loop"] = 5

    if len(svcs) > 100 {
        conf["delay_loop"] = 10
    }
    if len(svcs) > 1000 {
        conf["delay_loop"] = 30
    }

	conf["l7vipIsEmpty"] = len(settings.L7VIP) == 0
	conf["vrid_ingress"] = k.vrid + 1
	conf["priority_ingress"] = 1000 - k.priority // k.priority is 100 + nodeIndex, assume we will not have >= 900 nodes.
	conf["L7VIP"] = settings.L7VIP
	conf["L7HttpPort"] = settings.L7HttpPort
	conf["L7HttpsPort"] = settings.L7HttpsPort
	conf["l7eps"] = settings.L7Ep

	if glog.V(2) {
		b, _ := json.Marshal(conf)
		glog.Infof("%v", string(b))
	}

	err = k.keepalivedTmpl.Execute(w, conf)
	if err != nil {
		return fmt.Errorf("unexpected error creating keepalived.cfg: %v", err)
	}

	if k.proxyMode {
		w, err := os.Create(haproxyCfg)
		if err != nil {
			return err
		}
		defer w.Close()
		err = k.haproxyTmpl.Execute(w, conf)
		if err != nil {
			return fmt.Errorf("unexpected error creating haproxy.cfg: %v", err)
		}
	}
	return nil
}

// getVIPs returns a list of the virtual IP addresses to be used in keepalived
// without duplicates (a service can use more than one port)
func getVIPs(svcs []vip) []string {
	result := []string{}
	for _, svc := range svcs {
		result = appendIfMissing(result, svc.IP)
	}

	return result
}

//----------------------------------------------------
// Update the L4 exception rules in iptables PREROUTING chain, to ignore kube-proxy rules to treat VIP as external-ip
// FIXME, the code is almost exactlly the same as Update L7 Rules
//---------------------------------------------------
func (k *keepalived) UpdateL4IgnoreRules( currentL4Vips []string ) error {

    //Exactly Get the IP newly added and removed
    newlyAddIP := []string{}
    removedIP  := []string{}
    currentMap := make(map[string]bool)
    oldMap := make(map[string]bool)
    combineMap := make(map[string]bool)
    for _, newIP := range currentL4Vips{
        combineMap[newIP] = true
        currentMap[newIP] = true
    }
    for _, oldIP := range k.previousL4Vips{
        combineMap[oldIP] = true
        oldMap[oldIP] = true
    }
    // Those disappeared in currentMap
    for ip := range combineMap{
        if _, ok := currentMap[ip]; !ok {
            removedIP = append(removedIP, ip)
        }
    }
    // Those newly appear, comparing oldMap
    for ip := range combineMap{
        if _, ok := oldMap[ip]; !ok {
            newlyAddIP = append(newlyAddIP, ip)
        }
    }

    if len(newlyAddIP) == 0 && len(removedIP) == 0{
        // no change
        return nil
    }
    // Copy new array to old
    k.previousL4Vips= make( []string,len(currentL4Vips) )
    n := copy( k.previousL4Vips,  currentL4Vips )
    if n != len(currentL4Vips) {
        return fmt.Errorf("Error: Failed to copy currentL4Vips slices to k.previousL4Vips, copied elements = %d\n", n)
    }


    iptbl := " iptables-legacy -w 2 "
    glog.Infof("Info: Detected changes in currentL4Vips:  old =%v, new =%v\n", k.previousL4Vips, currentL4Vips)

    for _,vip :=range removedIP {
        removeOldRulesCmd := iptbl + " -t nat -nxvL PREROUTING --line | grep \""+ k.IgnoreKubeProxyKey
        removeOldRulesCmd += "\" | grep " + vip + " | awk '{print $1}'|head -n1|xargs iptables-legacy -t nat -D PREROUTING"
        // remove old rules matched the comments "$k.snatExceptionKey"
        errRev, _, errMsgRev := execShellCommand(removeOldRulesCmd)
        if errRev != nil {
            glog.Infof( "[Warning] removing old L4 ignore kube-proxy iptables rule failure(maybe just start up): (%v): %v  stderr=%v\n", removeOldRulesCmd, errRev, errMsgRev )
        }
    }
    for _,ip :=range newlyAddIP {
        // insert new rules to the top
        insertCmd :=  iptbl + " -t nat -I PREROUTING -d " + ip + " -j RETURN  -m comment --comment \"" + k.IgnoreKubeProxyKey + "\""
        err, outMsg, errMsg := execShellCommand(insertCmd)
        if err != nil {
            glog.Errorf( "Insert L4 ignore kube-proxy exception rules Failure: (%v): %v , stdout=%v, stderr=%v\n", insertCmd, err, outMsg, errMsg )
            return err
        }
    }

    glog.Info("Info: Update new ignore-kube-proxy rules into iptables for new L4 VIPS : Done")
    return nil


}


//----------------------------------------------------
// Update the L7 exception rules in iptables customized chain
//---------------------------------------------------
func (k *keepalived) UpdateL7ExceptionRules( currentL7Eps []l7endpoints) error {


    //FIXME, should check if rules missing. len(existing rule) == len(l7Vips)

    if ( len(currentL7Eps) == len( k.l7eps) ){
        changesDetected := false
        for _, newIP := range currentL7Eps{
            thisIPChanged := true
            for _, oldIP := range k.l7eps {
                if oldIP == newIP.Ip{
                    thisIPChanged = false
                    break
                }
            }
            if thisIPChanged {
                changesDetected = true
                break;
            }
        }
        if changesDetected == false {
            return nil
        }
    }
    glog.Infof("Info: Detected changes in currentL7Eps:  old =%v, new =%v\n", k.l7eps, currentL7Eps)



    removeOldRulesCmd := "iptables-legacy-save | grep -v " +  k.snatExceptionKey + " | iptables-legacy-restore " // remove old rules matched the comments "$k.snatExceptionKey"

    errRev, _, errMsgRev := execShellCommand( removeOldRulesCmd )
    if errRev != nil {
        glog.Infof( "[Warning] removing old L7 exception iptables rule failure(maybe just start up): (%v): %v  stderr=%v\n", removeOldRulesCmd, errRev, errMsgRev )
    }
    cmds := []string { }
    iptbl := " iptables-legacy -w 2 "
    //Compare currentL7Eps and old record, to determine whether to update iptables
    for _, l7ep := range currentL7Eps {
        // insert new rules to the top
        insertCmd_1 :=  iptbl + " -t nat -I " + k.snatChain + " -d " + l7ep.Ip + " -p tcp --dport " +  strconv.Itoa(l7ep.HttpPort) + " -j RETURN  -m comment --comment \"" + k.snatExceptionKey + "\""
        insertCmd_2 :=  iptbl + " -t nat -I " + k.snatChain + " -d " + l7ep.Ip + " -p tcp --dport " +  strconv.Itoa(l7ep.HttpsPort) + " -j RETURN  -m comment --comment \"" + k.snatExceptionKey + "\""
        cmds = append( cmds, insertCmd_1 )
        cmds = append( cmds, insertCmd_2 )
    }
    for _,cmdStr := range cmds {
        err, outMsg, errMsg := execShellCommand( cmdStr )
        if err != nil {
            glog.Errorf( "InsertL7ExceptionRules Failure: (%v): %v , stdout=%v, stderr=%v\n", cmdStr, err, outMsg, errMsg )
            return err
        }
    }

    // Copy new array to old
    k.l7eps = nil
    k.l7eps= make( []string,len(currentL7Eps) )
    //n := copy( k.l7eps,  currentL7Eps )
    for _, ep := range currentL7Eps{
        k.l7eps = append(k.l7eps, ep.Ip)
    }


    glog.Info("Info: Update new rules into iptables for new L7 VIPS : Done")
    return nil
}

//====================================================
//====================================================
func (k *keepalived) KernelOptimize(set bool) {
    cmdStr := "/optimize.sh"
    if set {
        cmdStr += " set"
        glog.Infof("kernel optimization set...")
    }else{
        cmdStr += " unset"
        glog.Infof("kernel optimization unset...")
    }
    err, outMsg, errMsg := execShellCommand( cmdStr )
    if err != nil {
        glog.Fatalf( "Error optimize kernel parameters (set=%v) : (%v): %v , stdout=%v, stderr=%v\n", set, cmdStr, err, outMsg, errMsg )
    }
}

//====================================================
// since LVS NAT mode doesn't do the SNAT by default, so here we set it up on host
//====================================================
func (k *keepalived) SetupIptablesSNAT() {
    glog.Infof("set up snat iptables...     ")
	// Q&A:
	// Q: Why not using k8s.io/kubernetes/pkg/util/iptables?
	// A: Here we setup Legacy iptables rules instead of nf_table iptable
	iptbl := " iptables-legacy -w 2 " // wait 2 sec for xtables lock
	targetCidr := "0.0.0.0/0"
    errPrefix := "Error setup iptables SNAT rules"
    cmdList := []string{
        iptbl + "-t nat -N " + k.snatChain, // 1.create a new customized chain
        iptbl + "-t nat -A " + k.snatChain + " -d " + targetCidr + " -j MASQUERADE" ,// 2. add a rule , SNAT all
        iptbl + "-t nat -I POSTROUTING -j " + k.snatChain, // 3. add this custmized chain to the top of POSTROUTING chain
    }
    for _,cmdStr := range cmdList {
        err, outMsg, errMsg := execShellCommand( cmdStr )
        if err != nil {
            glog.Fatalf( errPrefix + "(%v): %v , stdout=%v, stderr=%v\n", cmdStr, err, outMsg, errMsg )
        }
    }
}
//====================================================
// delete the customized iptables chain which keepalived-vip container set up  on host 
//====================================================
func (k *keepalived) CleanupIptablesSNAT(igore_error bool) {
	iptbl := " iptables-legacy -w 2 "
	glog.Infof("cleanup snat iptables...        (igore_error=%v)",igore_error)
    errPrefix := "problem encountered when cleanup iptables SNAT rules"

    cmdList := []string{
        iptbl + "-t nat -D POSTROUTING -j " + k.snatChain, // remove chain from POSTROUTING
	    iptbl + "-t nat -F " + k.snatChain,  // flush chain
	    iptbl + "-t nat -X " + k.snatChain,  // delete chain
    }
    for _,cmdStr := range cmdList {
        err, outMsg, errMsg := execShellCommand( cmdStr )
        if err != nil {
            msg := fmt.Sprintf(errPrefix + "(%v): %v , stdout=%v, stderr=%v\n", cmdStr, err, outMsg, errMsg)
            if igore_error{
                glog.Info("Warning(ignore error):" + msg)
            } else {
                glog.Fatalf("Error:" + msg)
            }
        }

    }
}
// Start starts a keepalived process in foreground.
// In case of any error it will terminate the execution with a fatal error
func (k *keepalived) Start() {
	ae, err := k.ipt.EnsureChain(iptables.TableFilter, iptables.Chain(iptablesChain))
	if err != nil {
		glog.Fatalf("unexpected error: %v", err)
	}
	if ae {
		glog.V(2).Infof("chain %v already existed", iptablesChain)
	}


	args := []string{"--dont-fork", "--log-console", "--log-detail"}
	if k.releaseVips {
		args = append(args, "--release-vips")
	}

	k.cmd = exec.Command("keepalived", args...)

	k.cmd.Stdout = os.Stdout
	k.cmd.Stderr = os.Stderr

	k.cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	k.started = true

    k.KernelOptimize(true)
    glog.Info("starting Setup SNAT iptables rules")
    k.CleanupIptablesSNAT(true) // cleanup first, to avoid dirty enviroment . Ignore failure
    k.SetupIptablesSNAT()

	glog.Info("starting keepalived process...")

	if err := k.cmd.Run(); err != nil {
		glog.Fatalf("Error starting keepalived: %v", err)
	}
}

// Reload sends SIGHUP to keepalived to reload the configuration.
func (k *keepalived) Reload() error {
	glog.Info("Waiting for keepalived to start")
	for !k.IsRunning() {
		time.Sleep(time.Second)
	}

	glog.Info("reloading keepalived")
	err := syscall.Kill(k.cmd.Process.Pid, syscall.SIGHUP)
	if err != nil {
		return fmt.Errorf("error reloading keepalived: %v", err)
	}

	return nil
}

// Whether keepalived process is currently running
func (k *keepalived) IsRunning() bool {
	if !k.started {
		glog.Error("keepalived not started")
		return false
	}

	if _, err := os.Stat(keepalivedPid); os.IsNotExist(err) {
		glog.Error("Missing keepalived.pid")
		return false
	}

	return true
}
////////////////////////////////////////////////
//
////////////////////////////////////////////////
func (k *keepalived) stringToInt( input []string )( []int, error){
	ret := []int{}
	for _, s := range input {
	   factor := 1
	   unit := strings.ToLower( string(s[len(s)-1]) )
	   switch {
	      case unit == "k" :
	          s = s[ : len(s)-1 ] //remove the unit
	          factor = 1024
	       case unit == "m" :
	          s = s[ : len(s)-1 ]
	          factor = 1024*1024
	        case unit == "g" :
	          s = s[ : len(s)-1 ]
	          factor = 1024*1024*1024
	        case unit == "t" :
	          s = s[ : len(s)-1 ]
	          factor = 1024*1024*1024*1024
	        //default:
	          //skip invalid unit check
	   }
	   v, err := strconv.Atoi(s)
	   if err != nil {
	       return ret, err
	   }
	   ret = append( ret, v * factor )
	}
	return ret, nil
}

/////////////////////////////////////////////////////
// the input should looks like IP:Port 0 1 2 3 4 5 6 7 8 9
//////////////////////////////////////////////////
func (k *keepalived) decodeMetricsLine( input []string )( ip string, port int32, values []int,  err error){
	if len(input) != 11 {
	    return "",0, []int{}, fmt.Errorf("ipvsadm parsing error: input array length invalid = %v, length=%v", input, len(input))
	}
	ipPort := input[0]
	ipAndPort  := strings.Split( ipPort, ":" )
	ip   = ipAndPort[0]
	portInt := 0
	portInt, err = strconv.Atoi(  ipAndPort[1] )
	port = int32(portInt)
	if err != nil {
	    return "",0, []int{}, fmt.Errorf("ipvsadm parsing error: failed to convert VIP port to int : %v" , ipAndPort[1])
	}
	port = int32(port)
	values , err  = k.stringToInt( input[1:] )
	if err != nil {
	    return "",0, []int{}, fmt.Errorf("ipvsadm parsing error: failed to convert values to int %v", input[2:6] )
	}
	return ip, port, values, nil

}

/////////////////////////////////////////////////////////////
func (k *keepalived) Metrics2Prom( metricsList []vipMetrics) (output *bytes.Buffer ) {
    output  = bytes.NewBufferString("")
    prefix := "l4_"
    metrics_prefix := prefix + "vip_"
    for _,l4 := range metricsList {
        label := " {" + "vip=\""   + l4.Vip  +  "\","
        label += "port=\""  + strconv.Itoa(int(l4.Port)) +  "\","
        label += "protocol=\""  + l4.Protocol +  "\""
        label += "} "
        output.WriteString( metrics_prefix + "conns"    + label + strconv.Itoa( l4.Conns ) + "\n" )
        output.WriteString( metrics_prefix + "in_pkts"   + label + strconv.Itoa( l4.InPkts )   + "\n")
        output.WriteString( metrics_prefix + "out_pkts"  + label + strconv.Itoa( l4.OutPkts )  + "\n")
        output.WriteString( metrics_prefix + "in_bytes"  + label + strconv.Itoa( l4.InBytes )  + "\n")
        output.WriteString( metrics_prefix + "out_bytes" + label + strconv.Itoa( l4.OutBytes ) + "\n")
        output.WriteString( metrics_prefix + "cps"      + label + strconv.Itoa( l4.CPS )      + "\n")
        output.WriteString( metrics_prefix + "in_pps"    + label + strconv.Itoa( l4.InPPS )    + "\n")
        output.WriteString( metrics_prefix + "out_pps"   + label + strconv.Itoa( l4.OutPPS )   + "\n")
        output.WriteString( metrics_prefix + "in_bps"    + label + strconv.Itoa( l4.InBPS )    + "\n")
        output.WriteString( metrics_prefix + "out_bps"   + label + strconv.Itoa( l4.OutBPS )   + "\n")
    }
    metrics_prefix = prefix + "endpoint_"
    for _,l4 := range metricsList {
        for _,ep := range l4.Eps{
            label := " {" + "ep_ip=\"" + ep.EpIp + "\","
            label +=        "ep_port=\"" + strconv.Itoa( int(ep.EpPort)) + "\""
            label += "} "
            output.WriteString( metrics_prefix + "conns"    + label + strconv.Itoa( ep.Conns )  + "\n" )
            output.WriteString( metrics_prefix + "in_pkts"   + label + strconv.Itoa( ep.InPkts ) + "\n" )
            output.WriteString( metrics_prefix + "out_pkts"  + label + strconv.Itoa( ep.OutPkts ) + "\n" )
            output.WriteString( metrics_prefix + "in_bytes"  + label + strconv.Itoa( ep.InBytes )+ "\n" )
            output.WriteString( metrics_prefix + "out_bytes" + label + strconv.Itoa( ep.OutBytes )+ "\n" )
            output.WriteString( metrics_prefix + "cps"      + label + strconv.Itoa( ep.CPS )    + "\n" )
            output.WriteString( metrics_prefix + "in_pps"    + label + strconv.Itoa( ep.InPPS )  + "\n" )
            output.WriteString( metrics_prefix + "out_pps"   + label + strconv.Itoa( ep.OutPPS ) + "\n" )
            output.WriteString( metrics_prefix + "in_bps"    + label + strconv.Itoa( ep.InBPS )  + "\n" )
            output.WriteString( metrics_prefix + "out_bps"   + label + strconv.Itoa( ep.OutBPS ) + "\n" )
       }
    }
    //NOTE, in go, the "string +" is very very slow due to dynamic allocation of space
    return output
}

////////////////////////////////////////////////////////////
func (k *keepalived) VipInfo() ( info vipInfo , err error) {
    var hostName bytes.Buffer
    hostCmd := exec.Command("hostname")
    hostCmd.Stdout = &hostName
    err = hostCmd.Run()
    if err != nil {
        return info, err
    }
    info.MasterNodeName = strings.Trim( hostName.String(), "\n")
    return info, err
}

///////////////////////////////////////////////////////////////////
func (k *keepalived) MetricsSummary() ( summary metricsStruct, err error) {
    info, err_n := k.VipInfo()
    if err_n != nil {
        return summary, err_n
    }
    summary.NodeName = info.MasterNodeName
    metricsData, err_m := k.Metrics()
    if err_m != nil {
        summary.MetricsData = []vipMetrics{}
        return summary, err_m
    }
    summary.MetricsData = metricsData
    vip_sums := []vipSummary{}
    for _, vip_port := range metricsData {
        index := -1 // idx of this vip in vip_sums[]
        for i, vs := range vip_sums{
            if vs.Vip == vip_port.Vip{
                index = i
                break
            }
        }
        if index == -1 {
            new_vs := vipSummary{}
            new_vs.Vip = vip_port.Vip
            new_vs.Conns = vip_port.Conns
            new_vs.InPkts = vip_port.InPkts
            new_vs.OutPkts = vip_port.OutPkts
            new_vs.InBytes = vip_port.InBytes
            new_vs.OutBytes = vip_port.OutBytes
            new_vs.CPS = vip_port.CPS
            new_vs.InPPS = vip_port.InPPS
            new_vs.OutPPS = vip_port.OutPPS
            new_vs.InBPS = vip_port.InBPS
            new_vs.OutBPS = vip_port.OutBPS
            vip_sums = append(vip_sums, new_vs)
        }else{
            vip_sums[index].Conns += vip_port.Conns
            vip_sums[index].InPkts += vip_port.InPkts
            vip_sums[index].OutPkts += vip_port.OutPkts
            vip_sums[index].InBytes += vip_port.InBytes
            vip_sums[index].OutBytes += vip_port.OutBytes
            vip_sums[index].CPS += vip_port.CPS
            vip_sums[index].InPPS += vip_port.InPPS
            vip_sums[index].OutPPS += vip_port.OutPPS
            vip_sums[index].InBPS += vip_port.InBPS
            vip_sums[index].OutBPS += vip_port.OutBPS
        }
    }
    summary.VipsSum = vip_sums
    return summary, nil
}
////////////////////////////////////////////////////////////
func (k *keepalived) Metrics() ( metricsList []vipMetrics, err error) {
	var out bytes.Buffer
	cmdStr :=  "export F1=/tmp/m1 && export F2=/tmp/m2 "
	cmdStr +=   "&& ipvsadm -Ln  --stats | tail -n +4  > $F1 " // skip first 3 lines of header, and echo to $F1
	cmdStr +=   "&& ipvsadm -Ln  --rate  | tail -n +4 | awk '{print $3 \"\\t\" $4 \"\\t\" $5 \"\\t\" $6 \"\\t\" $7 }' > $F2" // skip IP/port columes
	cmdStr +=   "&& l1=$(wc $F1 -l|awk '{print $1}') "
	cmdStr +=   "&& l2=$(wc $F2 -l|awk '{print $1}') "
	cmdStr +=   "&& if [ $l1 -eq $l2 ]; then   paste -d\"\\t\" $F1  $F2 ; fi" // concat two file vertically
	//cmdStr +=   " && rm $F1 $F2" // to speed up, not to remove them..
	glog.Infof("metrics command : %s\n", cmdStr)
	cmd := exec.Command("bash", "-c", cmdStr )
	cmd.Stderr = os.Stderr
	cmd.Stdout = &out
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	err = cmd.Run()
	if err != nil {
		return metricsList, err
	}

	outstr := strings.Split(out.String(), "\n")

	cnt := -1
	for _, line := range outstr {
	    if len(line) <=1 {
	        continue;
	    }
	    if ( ! strings.Contains(line, "->") ) {
	        // vip line: TCP  10.6.111.111:40002  0 0 0 0 0...
	        metcs := vipMetrics{}
	        arr := strings.Fields(line)
	        metcs.Protocol = arr[0]
	        values := []int{}
	        metcs.Vip, metcs.Port, values, err = k.decodeMetricsLine( arr[1:] )
	        if err != nil {
	            return metricsList, fmt.Errorf("ipvsadm parsing vip line error: error from decodeMetricsLine() = %v", err )
	        }
	        metcs.Conns   = values[0]
	        metcs.InPkts  = values[1]
	        metcs.OutPkts = values[2]
	        metcs.InBytes = values[3]
	        metcs.OutBytes = values[4]

	        metcs.CPS    = values[5]
	        metcs.InPPS  = values[6]
	        metcs.OutPPS = values[7]
	        metcs.InBPS  = values[8]
	        metcs.OutBPS = values[9]

	        metricsList = append( metricsList, metcs )
	        cnt ++
	    }else{
	        if (cnt < 0){
	            return metricsList, fmt.Errorf("ipvsadm parsing error: endpoint should follow the vip line.output= %v", outstr)
	        }
	        // ep lines  :   -> 172.28.210.141:80  0 0  0  0  0
	        epM := epMetrics{}
	        arr := strings.Fields(line)
	        values := []int{}
	        epM.EpIp, epM.EpPort, values, err = k.decodeMetricsLine( arr[1:] )
	        if err != nil {
	            return metricsList, fmt.Errorf("ipvsadm parsing ep line error: error from decodeMetricsLine() = %v", err )
	        }
	        epM.Conns   = values[0]
	        epM.InPkts  = values[1]
	        epM.OutPkts = values[2]
	        epM.InBytes = values[3]
	        epM.OutBytes = values[4]

	        epM.CPS    = values[5]
	        epM.InPPS  = values[6]
	        epM.OutPPS = values[7]
	        epM.InBPS  = values[8]
	        epM.OutBPS = values[9]

	        metricsList[cnt].Eps = append( metricsList[cnt].Eps, epM )
	    }
	}
	return metricsList, nil
}

// Whether keepalived child process is currently running and VIPs are assigned
func (k *keepalived) Healthy() error {
	if !k.IsRunning() {
		return fmt.Errorf("keepalived is not running")
	}

	if _, err := os.Stat(vrrpPid); os.IsNotExist(err) {
		return fmt.Errorf("VRRP child process not running")
	}
    if len( k.vips ) == 0{
        // no any vip from configmap, so ignore for now
        return nil
    }
	b, err := ioutil.ReadFile(keepalivedState)
	if err != nil {
		return err
	}

	master := false
	state := strings.TrimSpace(string(b))
	if strings.Contains(state, "MASTER") {
		master = true
	}

	var out bytes.Buffer
	cmd := exec.Command("ip", "-brief", "address", "show", k.iface, "up")
	cmd.Stderr = os.Stderr
	cmd.Stdout = &out
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	err = cmd.Run()
	if err != nil {
		return err
	}

	ips := out.String()
	glog.V(3).Infof("Status of %s interface: %s", state, ips)

	for _, vip := range k.vips {
		containsVip := strings.Contains(ips, fmt.Sprintf(" %s/32 ", vip))

		if master && !containsVip {
			return fmt.Errorf("Missing VIP %s on %s", vip, state)
		} else if !master && containsVip {
			return fmt.Errorf("%s should not contain VIP %s", state, vip)
		}
	}
    //check if ipvsadm -L -n still contains the VIP items
    cmdStr := "ipvsadm -L -n "
    _, outMsg, _ := execShellCommand( cmdStr )
    for _, vip := range k.vips {
        containsVip := strings.Contains( outMsg, vip )
        glog.Infof(" DEBUG, in Health(): ipvsadm contains %s  ? result  %s", vip, containsVip)
        if !containsVip{
            return fmt.Errorf("Error: Missing L4 VIP rule for vip:%s on ipvsadm rules list %s", vip, outMsg )
        }
    }
    if !  strings.Contains( outMsg, k.l7vip ) {
       return fmt.Errorf("Error: Missing L7 VIP rule for L7 endpoint :%s on ipvsadm rules list %s", k.l7vip, outMsg )
    }

	// All checks successful
	return nil
}

func (k *keepalived) Cleanup() {
    k.CleanupIptablesSNAT(false)

    // Deleting the Ignore-Kube-Proxy Rules for L4 VIP
    iptbl := " iptables-legacy -w 2 "
    cmds := []string { }
    for _, vip :=range k.vips{
        // insert new rules to the top
        delcmd := iptbl + " -t nat -nxvL PREROUTING --line | grep \""+ k.IgnoreKubeProxyKey
        delcmd += "\" | grep " + vip + " | awk '{print $1}'|head -n1|xargs iptables-legacy -t nat -D PREROUTING"
        cmds = append( cmds, delcmd)
    }
    for _,cmdStr := range cmds {
        err, outMsg, errMsg := execShellCommand( cmdStr )
        if err != nil {
            glog.Errorf( "Deleting L4 ignore kube-proxy exception rules Failure: (%v): %v , stdout=%v, stderr=%v\n", cmdStr, err, outMsg, errMsg )
        }
    }



    // DCE: clean Strategic Routing when exists
    cleanRoutingWhenAsBackup := fmt.Sprintf("/routing.sh unset %v", k.vrid)
    errCleanRouting, _ , errMsg := execShellCommand( cleanRoutingWhenAsBackup  )
    if errCleanRouting != nil{
        glog.Errorf("Warning: Unable to clean Routing table setup for backup node, please clean up manually. err=%v, err_msg=%v", errCleanRouting, errMsg)
    }else{
        glog.Infof("successfully clean routing tables, command  %v", cleanRoutingWhenAsBackup)
    }


	err := k.ipt.FlushChain(iptables.TableFilter, iptables.Chain(iptablesChain))
	if err != nil {
		glog.V(2).Infof("unexpected error flushing iptables chain %v: %v", err, iptablesChain)
	}

    outp, err_chk := k8sexec.New().Command("/check_cleanup.sh", " >>" , "/var/log/keepalived-cleanup.log").CombinedOutput()
    if err_chk != nil{
        glog.Infof("Cleanup Check iptables : Error: [%s] [%s]", err_chk, outp )
    }else{
        glog.Infof("Cleanup Check iptables : %s", outp )
    }

	glog.Infof("Cleanup VIPs: %s", k.vips)
	for _, vip := range k.vips {
		k.removeVIP(vip)
	}
	glog.Infof("Cleanup VIP: %s", k.l7vip)
    if k.l7vip != ""{
        k.removeVIP(k.l7vip)
    }

}

// Stop stop keepalived process
func (k *keepalived) Stop() {

	k.KernelOptimize(false)
	k.Cleanup()
	err := syscall.Kill(k.cmd.Process.Pid, syscall.SIGTERM)
	if err != nil {
		glog.Errorf("error stopping keepalived: %v", err)
	}
}

func (k *keepalived) removeVIP(vip string) {
	glog.Infof("removing configured VIP %v", vip)
	out, err := k8sexec.New().Command("ip", "addr", "del", vip+"/32", "dev", k.iface).CombinedOutput()
	if err != nil {
        //maybe this is the backup node, doesn't own the vip
		glog.V(2).Infof("Error removing VIP %s: on dev %s %v\n%s", vip, k.iface, err, out)
	}
}

func (k *keepalived) loadTemplates() error {
	tmpl, err := template.ParseFiles(keepalivedTmpl)
	if err != nil {
		return err
	}
	k.keepalivedTmpl = tmpl

	tmpl, err = template.ParseFiles(haproxyTmpl)
	if err != nil {
		return err
	}
	k.haproxyTmpl = tmpl

	return nil
}
