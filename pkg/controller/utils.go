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
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
    "strconv"

	"github.com/golang/glog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/aledbf/kube-keepalived-vip/pkg/k8s"
)

var (
	invalidIfaces = []string{"lo", "docker0", "flannel.1", "cbr0"}
	vethRegex     = regexp.MustCompile(`^veth.*`)
	caliRegex     = regexp.MustCompile(`^cali.*`)
	lvsRegex      = regexp.MustCompile(`NAT|DR|PROXY`)
    lbAlgoRegex   = regexp.MustCompile(`rr|wrr|lc|wlc|sh|dh|lblc|sed|nq`)
)

type nodeInfo struct {
	iface   string
	ip      string
	netmask int
}

type svcConfig struct {
    namespace string
    service   string
    port      int32
    lbAlgo    string
    lvKind    string
    weight    int

}

// getNetworkInfo returns information of the node where the pod is running
func getNetworkInfo(ip string) (*nodeInfo, error) {
	iface, mask, err := interfaceByIP(ip)
	if err != nil {
		return nil, err
	}
	return &nodeInfo{
		iface:   iface,
		ip:      ip,
		netmask: mask,
	}, nil
}

// netInterfaces returns a slice containing the local network interfaces
func netInterfaces() ([]net.Interface, error) {
	validIfaces := []net.Interface{}
	ifaces, err := net.Interfaces()
	if err != nil {
		glog.Errorf("unexpected error obtaining network interfaces: %v", err)
		return validIfaces, err
	}

	for _, iface := range ifaces {
		if !vethRegex.MatchString(iface.Name) &&
			!caliRegex.MatchString(iface.Name) &&
			stringSlice(invalidIfaces).pos(iface.Name) == -1 {
			validIfaces = append(validIfaces, iface)
		}
	}

	glog.V(2).Infof("network interfaces: %+v", validIfaces)
	return validIfaces, nil
}

type ipMask struct {
	ip   string
	mask int
}

// interfaceByIP returns the local network interface name that is using the
// specified IP address. If no interface is found returns an error
func interfaceByIP(ip string) (string, int, error) {
	ifaces, err := netInterfaces()
	if err != nil {
		return "", 0, err
	}

	for _, iface := range ifaces {
		ipMasks, err := ipsByInterface(iface.Name)
		if err != nil {
			continue
		}
		for _, ipMask := range ipMasks {
			if ip == ipMask.ip {
				return iface.Name, ipMask.mask, nil
			}
		}
	}

	return "", 0, fmt.Errorf("no matching interface found for IP %s", ip)
}

func ipsByInterface(name string) ([]ipMask, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	var ret []ipMask
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip := ipnet.IP.String()
				ones, _ := ipnet.Mask.Size()
				mask := ones
				ret = append(ret, ipMask{ip, mask})
			}
		}
	}

	return ret, nil
}

type stringSlice []string

// pos returns the position of a string in a slice.
// If it does not exists in the slice returns -1.
func (slice stringSlice) pos(value string) int {
	for p, v := range slice {
		if v == value {
			return p
		}
	}

	return -1
}

// getClusterNodesIP returns the IP address of each node in the kubernetes cluster
func getClusterNodesIP(kubeClient *kubernetes.Clientset, nodeSelector string) (clusterNodes []string) {
	listOpts := metav1.ListOptions{}

	if nodeSelector != "" {
		label, err := labels.Parse(nodeSelector)
		if err != nil {
			glog.Fatalf("'%v' is not a valid selector: %v", nodeSelector, err)
		}
		listOpts.LabelSelector = label.String()
	}

	nodes, err := kubeClient.CoreV1().Nodes().List(listOpts)
	if err != nil {
		glog.Fatalf("Error getting running nodes: %v", err)
	}

	for _, nodo := range nodes.Items {
		nodeIP := k8s.GetNodeIP(kubeClient, nodo.Name)
		clusterNodes = append(clusterNodes, nodeIP)
	}
	sort.Strings(clusterNodes)

	return
}

// getNodeNeighbors returns a list of IP address of the nodes
func getNodeNeighbors(nodeInfo *nodeInfo, clusterNodes []string) (neighbors []string) {
	for _, neighbor := range clusterNodes {
		if nodeInfo.ip != neighbor {
			neighbors = append(neighbors, neighbor)
		}
	}
	sort.Strings(neighbors)
	return
}

// getPriority returns the priority of one node using the
// IP address as key. It starts in 100
func getNodePriority(ip string, nodes []string) int {
	return 100 + stringSlice(nodes).pos(ip)
}

func appendIfMissing(slice []string, item string) []string {
	for _, elem := range slice {
		if elem == item {
			return slice
		}
	}
	return append(slice, item)
}

func parseNsName(input string) (string, string, error) {
	nsName := strings.Split(input, "/")
	if len(nsName) != 2 {
		return "", "", fmt.Errorf("invalid format (namespace/name) found in '%v'", input)
	}

	return nsName[0], nsName[1], nil
}
func parseAddress(address string) (string, int32, string, error) {
    re := regexp.MustCompile(`(.*)-(\d+)(-(.+))?`)
    matches := re.FindStringSubmatch(address)
    if matches == nil || len(matches) !=5{
        return "", 0, "", fmt.Errorf("invalid: address string: %q, should be in format of VIP-ExtPort ", address)
    }
    ip := matches[1]
    extPort, err := strconv.Atoi(matches[2])
    iface := matches[4]
    if err != nil {
        return "", 0, "",fmt.Errorf("invalid: address string: %q, port value should be int", address)
    }
    return ip, int32(extPort), iface, nil
}

func parseL4Config(input string) ( svcConfig, error) {

    conf := svcConfig{
        namespace:"default",
        service:"",
        port:0,
        lbAlgo:"wlc",
        lvKind:"NAT",
        weight:100,
    }

    lines := strings.Split(input,"\n")
    for _, line := range lines{
        kv := strings.Split( line,"=")
        if len(kv) != 2 {
            return conf, fmt.Errorf("invalid config format in '%v'", line)
        }
        k := kv[0]
        v := kv[1]
        switch {
        case k =="service":
            nsSvc := strings.Split( v ,"/")
            if len(nsSvc) != 2 {
                return conf, fmt.Errorf("invalid config format in '%v', should be namespace/service ", nsSvc )
            }
            conf.namespace = nsSvc[0]
            conf.service   = nsSvc[1]
        case k =="port":
            p, err := strconv.Atoi(v)
            if err != nil {
                return conf, fmt.Errorf("unrecognized port value '%v' in '%v'", v, line)
            }
            conf.port = int32(p)
        case k == "lbAlgo":
            if !lbAlgoRegex.MatchString(v){
                return conf, fmt.Errorf("invalid Load Balance method. rr|wrr|lc|wlc|sh|dh|lblc|nq|sed are supported: %v", v)
            }
            conf.lbAlgo = v
        case k == "lvKind":
            if !lvsRegex.MatchString(v){
                return conf, fmt.Errorf("invalid LVS method. Only NAT,DR and PROXY are supported: %v", v)
            }
            conf.lvKind = v
        case k == "weight":
            w, err := strconv.Atoi(v)
            if err != nil {
                return conf, fmt.Errorf("unrecognized weight value '%v' in '%v'", v, line)
            }
            conf.weight = w
        default:
            return conf, fmt.Errorf("unrecognized config key '%v' in '%v'", k, line)
        }

    }

	return conf, nil
}

type nodeSelector map[string]string

func (ns nodeSelector) String() string {
	kv := []string{}
	for key, val := range ns {
		kv = append(kv, fmt.Sprintf("%v=%v", key, val))
	}

	return strings.Join(kv, ",")
}

func parseNodeSelector(data map[string]string) string {
	return nodeSelector(data).String()
}
