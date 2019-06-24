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
	"crypto/md5"
	"encoding/hex"
    "encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"sort"
	"sync"
	"syscall"
    "strconv"
    "strings"
	"time"

	"github.com/golang/glog"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/flowcontrol"
	api "k8s.io/kubernetes/pkg/apis/core"

	utildbus "k8s.io/kubernetes/pkg/util/dbus"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"

	"github.com/aledbf/kube-keepalived-vip/pkg/k8s"
	"github.com/aledbf/kube-keepalived-vip/pkg/store"
	"github.com/aledbf/kube-keepalived-vip/pkg/task"
)

const (
	resyncPeriod = 0
)

type service struct {
	IP   string
	Port int
}

type serviceByIPPort []service

func (c serviceByIPPort) Len() int      { return len(c) }
func (c serviceByIPPort) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c serviceByIPPort) Less(i, j int) bool {
	iIP := c[i].IP
	jIP := c[j].IP
	if iIP != jIP {
		return iIP < jIP
	}

	iPort := c[i].Port
	jPort := c[j].Port
	return iPort < jPort
}
////////////////////////
//DCE customized ----
///////////////////////
type l7endpoints struct {
    Ip string
    HttpPort int
    HttpsPort int
    Weight int

}

type globalSetting struct {
    L4VIP string
    L7VIP string
    iface string
    L7HttpPort int
    L7HttpsPort int
    L7Ep  []l7endpoints
}

type vip struct {
	Name      string
	IP        string
    ExternalPort  int32
	ContainerPort int32  //old Port variable means ContainerPort
	Protocol  string
    LbMethod  string
	LVSMethod string
    PersistenceTimeout int
	Backends  []service
}

type vipByNameIPPort []vip

func (c vipByNameIPPort) Len() int      { return len(c) }
func (c vipByNameIPPort) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c vipByNameIPPort) Less(i, j int) bool {
	iName := c[i].Name
	jName := c[j].Name
	if iName != jName {
		return iName < jName
	}

	iIP := c[i].IP
	jIP := c[j].IP
	if iIP != jIP {
		return iIP < jIP
	}

	iPort := c[i].ContainerPort
	jPort := c[j].ContainerPort
	return iPort < jPort
}

// ipvsControllerController watches the kubernetes api and adds/removes
// services from LVS throgh ipvsadmin.
type ipvsControllerController struct {
	client *kubernetes.Clientset

	epController  cache.Controller
	map1Controller cache.Controller
	map2Controller cache.Controller
	svcController cache.Controller

	svcLister store.ServiceLister
	epLister  store.EndpointLister
	map1Lister store.ConfigMapLister
	map2Lister store.ConfigMapLister

	reloadRateLimiter flowcontrol.RateLimiter

	keepalived *keepalived

	configSvcMapName string
	configGlobalMapName string

	httpPort int

	ruMD5 string

	// stopLock is used to enforce only a single call to Stop is active.
	// Needed because we allow stopping through an http endpoint and
	// allowing concurrent stoppers leads to stack traces.
	stopLock sync.Mutex

	shutdown bool

	syncQueue *task.Queue

	stopCh chan struct{}

    willAddDNAT bool
}

// getEndpoints returns a list of <endpoint ip>:<port> for a given service/target port combination.
func (ipvsc *ipvsControllerController) getEndpoints(
	s *apiv1.Service, servicePort *apiv1.ServicePort) []service {
	ep, err := ipvsc.epLister.GetServiceEndpoints(s)
	if err != nil {
		glog.Warningf("unexpected error getting service endpoints: %v", err)
		return []service{}
	}

	var endpoints []service

	// The intent here is to create a union of all subsets that match a targetPort.
	// We know the endpoint already matches the service, so all pod ips that have
	// the target port are capable of service traffic for it.
	for _, ss := range ep.Subsets {
		for _, epPort := range ss.Ports {
			var targetPort int
			switch servicePort.TargetPort.Type {
			case intstr.Int:
				if int(epPort.Port) == servicePort.TargetPort.IntValue() {
					targetPort = int(epPort.Port)
				}
			case intstr.String:
				if epPort.Name == servicePort.TargetPort.StrVal {
					targetPort = int(epPort.Port)
				}
			}
			if targetPort == 0 {
				continue
			}
			for _, epAddress := range ss.Addresses {
				endpoints = append(endpoints, service{IP: epAddress.IP, Port: targetPort})
			}
		}
	}

	return endpoints
}
// get global setting from configmap
func (ipvsc *ipvsControllerController) getGlobalSetting(cfgMap *apiv1.ConfigMap) ( globalSetting, error ) {
    setting := globalSetting{
        L4VIP: "",
        L7VIP : "",
        iface : "ens192",
        L7HttpPort:  80,
        L7HttpsPort: 443,
        L7Ep  : make([]l7endpoints, 0),
    }

    for k,v :=  range cfgMap.Data{
        switch  {
        case k == "L4VIP":
            setting.L4VIP = v
        case k == "L7VIP":
            setting.L7VIP = v
        case k == "iface":
            setting.iface = v
        case k == "L7HttpPort":
            intV, err := strconv.Atoi(v)
            if err != nil{
                return setting, fmt.Errorf("Invalid numberic value= %v,for key %v in configmap \n", v, k )
            }
            setting.L7HttpPort = intV
        case k == "L7HttpsPort":
            intV, err := strconv.Atoi(v)
            if err != nil{
                return setting, fmt.Errorf("Invalid numberic value= %v,for key %v in configmap \n", v, k )
            }
            setting.L7HttpsPort = intV
        case strings.Contains(k,"instance"):
           // assume this is a L7 End point, key is the IP, value is multiple lines
            ep := l7endpoints{
                Ip : "",
                HttpPort: 80,
                HttpsPort: 443,
                Weight: 1,
            }
            outstr := strings.Split(v,"\n")

            for _, line := range  outstr {
                prop := strings.Split( line,"=")
                switch strings.ToLower(prop[0]) {
                case "ip":
                    ep.Ip = prop[1]
                case "httpport":
                    intV, err := strconv.Atoi(prop[1])
                    if err != nil{
                        return setting, fmt.Errorf("Invalid numberic value= %v,for key %v in configmap \n", prop[1], prop[0] )
                    }
                    ep.HttpPort = intV
                case "httpsport":
                    intV, err := strconv.Atoi(prop[1])
                    if err != nil{
                        return setting, fmt.Errorf("Invalid numberic value= %v,for key %v in configmap \n", prop[1], prop[0] )
                    }
                    ep.HttpsPort = intV
                case "weight":
                    intV, err := strconv.Atoi(prop[1])
                    if err != nil{
                        return setting, fmt.Errorf("Invalid numberic value= %v,for key %v in configmap \n", prop[1], prop[0] )
                    }
                    ep.Weight = intV
                default:
                    return setting, fmt.Errorf("Unrecognized key in configmap :%v\n", prop[0])
                }
            }
            if ep.Ip == ""{
                return setting, fmt.Errorf(" IP should not be blank for L7 endpoint in configMap, key=%v \n", k )
            }
            setting.L7Ep = append( setting.L7Ep, ep )

            //sort it to guarrentee order, to avoid Config file keeping changed
            sort.Slice( setting.L7Ep, func(i, j int) bool {
                    return strings.Compare( setting.L7Ep[i].Ip , setting.L7Ep[j].Ip ) > 0
            })

        default:
            return setting, fmt.Errorf("Unrecognized key %v in global configmap ", k)
        } // end of switch

    } // end of for range cfgMap.Data

    return setting, nil
}


// getServices returns a list of services and their endpoints.
func (ipvsc *ipvsControllerController) getServices(cfgMap *apiv1.ConfigMap) []vip {
	svcs := []vip{}

	// k -> IP to use
	// v -> <namespace>/<service name>:<lvs method>
	for address, nsSvcLvs := range cfgMap.Data {

        externalIP, extPort, iface, err := parseAddress(address)
		if err != nil {
			glog.Warningf("%v", err)
			continue
		}
        glog.V(2).Infof("parsed externalIP =%v, extPort = %v, iface=%v ", externalIP, extPort, iface)

		if nsSvcLvs == "" {
			// if target is empty string we will not forward to any service but
			// instead just configure the IP on the machine and let it up to
			// another Pod or daemon to bind to the IP address
			svcs = append(svcs, vip{
				Name:      "",
				IP:        externalIP,
                ContainerPort: 0,
                ExternalPort:  extPort,
				LbMethod:  "wlc",
				LVSMethod: "VIP",
				Backends:  nil,
				Protocol:  "TCP",
                PersistenceTimeout : 1800,
			})
			glog.V(2).Infof("Adding VIP only service: %v", externalIP)
			continue
		}

        svcConf , err := parseL4Config(nsSvcLvs)

		if err != nil {
			glog.Warningf("%v", err)
			continue
		}
		nsSvc := fmt.Sprintf("%v/%v", svcConf.namespace , svcConf.service )
		svcObj, svcExists, err := ipvsc.svcLister.Store.GetByKey(nsSvc)
		if err != nil {
			glog.Warningf("error getting service %v: %v", nsSvc, err)
			continue
		}

		if !svcExists {
			glog.Warningf("service %v not found", nsSvc)
			continue
		}

		s := svcObj.(*apiv1.Service)
		for _, servicePort := range s.Spec.Ports {
			ep := ipvsc.getEndpoints(s, &servicePort)
			if len(ep) == 0 {
				glog.Warningf("no endpoints found for service %v, port %+v", s.Name, servicePort)
				continue
			}
            if int(svcConf.port) != servicePort.TargetPort.IntValue() { // should it be TargetPort or Port ? FIXME ?
                glog.Infof("skip port %v for service, because it was not explicitly specified in Config Map ",svcConf.service,  servicePort.TargetPort)
                continue
            }

			sort.Sort(serviceByIPPort(ep))

			svcs = append(svcs, vip{
				Name:      fmt.Sprintf("%v-%v", s.Namespace, s.Name),
				IP:        externalIP,
				ContainerPort: svcConf.port, //int32(servicePort.Port),
				ExternalPort:  extPort,
				LbMethod:  svcConf.lbAlgo,
				LVSMethod: svcConf.lvKind,
                PersistenceTimeout: svcConf.persistence_timeout,
				Backends:  ep,
				Protocol:  fmt.Sprintf("%v", servicePort.Protocol),
			})
			glog.V(2).Infof("found service: %v:%v", s.Name, servicePort.Port)
		}
	}

	sort.Sort(vipByNameIPPort(svcs))

	return svcs
}

// sync all services with the
func (ipvsc *ipvsControllerController) sync(key interface{}) error {
	ipvsc.reloadRateLimiter.Accept()

    //Retrive first COnfigMap : ipvsc.configSvcMapName
	ns_svc, name_svc, err_svc := parseNsName(ipvsc.configSvcMapName)
	if err_svc != nil {
		glog.Warningf("%v", err_svc)
		return err_svc
	}
	cfgMap_svc, err_gsvc := ipvsc.getConfigMap(ns_svc, name_svc)
	if err_gsvc != nil {
		return fmt.Errorf("unexpected error searching service configmap %v/%v: %v", ns_svc, name_svc , err_gsvc)
	}

	glog.V(2).Infof("ConfigMap Service =%v",cfgMap_svc)


    //DCE: Retrive second ConfigMap : ipvsc.configGlobalMapName
	ns_gb, name_gb, err_gb := parseNsName(ipvsc.configGlobalMapName)
	if err_gb != nil {
		glog.Warningf("%v", err_gb)
		return err_gb
	}
	cfgMap_gb, err_ggb := ipvsc.getConfigMap(ns_gb, name_gb)
	if err_ggb != nil {
		return fmt.Errorf("unexpected error searching global setup configmap %v/%v: %v", ns_gb, name_gb, err_ggb)
	}

	glog.V(2).Infof("ConfigMap Global =%v",cfgMap_gb)

    // get services config from service configMap
	svcs := ipvsc.getServices(cfgMap_svc)

    // get DCE specific globalSettings from cfgMap_gb ConfigMap
    globalSettings, err_gs := ipvsc.getGlobalSetting( cfgMap_gb )
    if err_gs != nil {
        return fmt.Errorf("unexpected error getting global setting from configmap %v: %v",  ipvsc.configGlobalMapName, err_gs )
    }

    glog.Infof("DEBUG globalSettings =  %v\n",globalSettings)

    // override global setting ,if service setting is blank
    for  i, svc := range svcs{
        if svc.IP == "" {
            svcs[i].IP = globalSettings.L4VIP
        }
    }

    // re-render the keepalived.conf 
    err := ipvsc.keepalived.WriteCfg(svcs, globalSettings)
	if err != nil {
		return err
	}

	glog.V(2).Infof("services: %v", svcs)

	md5, err := checksum(keepalivedCfg)
	if err == nil && md5 == ipvsc.ruMD5 {
		return nil
	}

	ipvsc.ruMD5 = md5
	err = ipvsc.keepalived.Reload()
	if err != nil {
		glog.Errorf("error reloading keepalived: %v", err)
	}

    //DCE Customized: Update the L7 Exception Rules in iptables
    l7eps := []string{}
    for _, l7ep := range globalSettings.L7Ep{
        l7eps = append( l7eps, l7ep.Ip)
    }
    errL7Rule := ipvsc.keepalived.UpdateL7ExceptionRules( l7eps )
    if errL7Rule != nil{
        glog.Errorf("Error when UpdateL7ExceptionRules: %v", errL7Rule)
    }

	return nil
}

// Stop stops the loadbalancer controller.
func (ipvsc *ipvsControllerController) Start() {
	go ipvsc.epController.Run(ipvsc.stopCh)
	go ipvsc.svcController.Run(ipvsc.stopCh)
	go ipvsc.map1Controller.Run(ipvsc.stopCh)
	go ipvsc.map2Controller.Run(ipvsc.stopCh)

	go ipvsc.syncQueue.Run(time.Second, ipvsc.stopCh)

	go handleSigterm(ipvsc)

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if !cache.WaitForCacheSync(ipvsc.stopCh,
		ipvsc.epController.HasSynced,
		ipvsc.svcController.HasSynced,
		ipvsc.map1Controller.HasSynced,
		ipvsc.map2Controller.HasSynced,
	) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
	}

	go func() {
		glog.Infof("Starting HTTP server on port %d", ipvsc.httpPort)
		err := http.ListenAndServe(fmt.Sprintf(":%d", ipvsc.httpPort), nil)
		if err != nil {
			glog.Error(err.Error())
		}
	}()

    glog.Info("starting Setup DNAT iptables rules")
    ipvsc.keepalived.CleanupIptablesDNAT(true) // cleanup first, to avoid dirty enviroment . Ignore failure
    ipvsc.keepalived.SetupIptablesDNAT()
	glog.Info("starting keepalived to announce VIPs")
	ipvsc.keepalived.Start()
}

func handleSigterm(ipvsc *ipvsControllerController) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)
	<-signalChan
	glog.Infof("Received SIGTERM, shutting down")

	exitCode := 0
	if err := ipvsc.Stop(); err != nil {
		glog.Infof("Error during shutdown %v", err)
		exitCode = 1
	}

	glog.Infof("Exiting with %v", exitCode)
	os.Exit(exitCode)
}

// Stop stops the loadbalancer controller.
func (ipvsc *ipvsControllerController) Stop() error {
	ipvsc.stopLock.Lock()
	defer ipvsc.stopLock.Unlock()

	if !ipvsc.syncQueue.IsShuttingDown() {
		glog.Infof("shutting down controller queues")
		close(ipvsc.stopCh)
		go ipvsc.syncQueue.Shutdown()
        ipvsc.keepalived.CleanupIptablesDNAT(false)
		ipvsc.keepalived.Stop()

        // DCE: clean Strategic Routing when exists
        cleanRoutingWhenAsBackup := " iptables-legacy -t mangle -nxvL OUTPUT |grep \"ingress routing rule\" && /routing.sh unset || exit 0"
        errCleanRouting, _ , errMsg := execShellCommand( cleanRoutingWhenAsBackup  )
        if errCleanRouting != nil{
            return fmt.Errorf("Warning: Unable to clean Routing table setup for backup node, please clean up manually. err=%v, err_msg=%v", errCleanRouting, errMsg)
        }else{
            glog.Info("successfully clean routing tables")
        }

		return nil
	}

	return fmt.Errorf("shutdown already in progress")
}

// NewIPVSController creates a new controller from the given config.
func NewIPVSController(kubeClient *kubernetes.Clientset, namespace string, useUnicast bool, configSvcMapName string, configGlobalMapName string, vrid int, proxyMode bool, iface string, httpPort int, releaseVips bool, willAddDNAT bool ) *ipvsControllerController {
	ipvsc := ipvsControllerController{
		client:            kubeClient,
		reloadRateLimiter: flowcontrol.NewTokenBucketRateLimiter(0.5, 1),
		configSvcMapName:     configSvcMapName,
        configGlobalMapName : configGlobalMapName,
		httpPort:          httpPort,
		stopCh:            make(chan struct{}),
        willAddDNAT:       willAddDNAT,
	}

	podInfo, err := k8s.GetPodDetails(kubeClient)
	if err != nil {
		glog.Fatalf("Error getting POD information: %v", err)
	}

	pod, err := kubeClient.CoreV1().Pods(podInfo.Namespace).Get(podInfo.Name, metav1.GetOptions{})
	if err != nil {
		glog.Fatalf("Error getting %v: %v", podInfo.Name, err)
	}

	selector := parseNodeSelector(pod.Spec.NodeSelector)
	clusterNodes := getClusterNodesIP(kubeClient, selector)

	nodeInfo, err := getNetworkInfo(podInfo.NodeIP)
	if err != nil {
		glog.Fatalf("Error getting local IP from nodes in the cluster: %v", err)
	}
	neighbors := getNodeNeighbors(nodeInfo, clusterNodes)

	notify := os.Getenv("KEEPALIVED_NOTIFY")

	if iface == "" {
		iface = nodeInfo.iface
		glog.Info("No interface was provided, proceeding with the node's default: ", iface)
	}
	execer := utilexec.New()
	dbus := utildbus.New()
	iptInterface := utiliptables.New(execer, dbus, utiliptables.ProtocolIpv4)

	ipvsc.keepalived = &keepalived{
		iface:       iface,
		ip:          nodeInfo.ip,
		netmask:     nodeInfo.netmask,
		nodes:       clusterNodes,
		neighbors:   neighbors,
		priority:    getNodePriority(nodeInfo.ip, clusterNodes),
		useUnicast:  useUnicast,
		ipt:         iptInterface,
		vrid:        vrid,
		proxyMode:   proxyMode,
		notify:     notify,
		releaseVips: releaseVips,
        dnatChain : "DCE_L4_DNAT_CHAIN",
        dnatExceptionKey: "DCE_L7_EXCEPTION_RULES",
	}

	ipvsc.syncQueue = task.NewTaskQueue(ipvsc.sync)

	err = ipvsc.keepalived.loadTemplates()
	if err != nil {
		glog.Fatalf("Error loading templates: %v", err)
	}

	mapEventHandler := cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				upCmap := cur.(*apiv1.ConfigMap)
				mapKey := fmt.Sprintf("%s/%s", upCmap.Namespace, upCmap.Name)
				// updates to configuration configmaps can trigger an update
				if mapKey == ipvsc.configSvcMapName || mapKey == ipvsc.configGlobalMapName {
					ipvsc.syncQueue.Enqueue(cur)
				}
			}
		},
	}

	eventHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ipvsc.syncQueue.Enqueue(obj)
		},
		DeleteFunc: func(obj interface{}) {
			ipvsc.syncQueue.Enqueue(obj)
		},
		UpdateFunc: func(old, cur interface{}) {
            if old.(*apiv1.Endpoints).Namespace == "kube-system" &&
            (   old.(*apiv1.Endpoints).Name == "kube-controller-manaer" ||
                old.(*apiv1.Endpoints).Name == "kube-scheduler" ) {
                // skip when ep changed in kube-system. due to kube-controller-manaer/kube-scheduler gets updated every second
                return
            }
			if !reflect.DeepEqual(old, cur) {
				ipvsc.syncQueue.Enqueue(cur)
			}
		},
	}

	ipvsc.svcLister.Store, ipvsc.svcController = cache.NewInformer(
		cache.NewListWatchFromClient(ipvsc.client.CoreV1().RESTClient(), "services", namespace, fields.Everything()),
		&apiv1.Service{}, resyncPeriod, cache.ResourceEventHandlerFuncs{})

	ipvsc.epLister.Store, ipvsc.epController = cache.NewInformer(
		cache.NewListWatchFromClient(ipvsc.client.CoreV1().RESTClient(), "endpoints", namespace, fields.Everything()),
		&apiv1.Endpoints{}, resyncPeriod, eventHandlers)

	cmns_svc, cmn_svc, err_svc := parseNsName(ipvsc.configSvcMapName)
	if err_svc != nil {
		glog.Fatalf("Error parsing configmap name: %v", err_svc)
	}

	cmns_gb, cmn_gb, err_gb := parseNsName(ipvsc.configGlobalMapName)
	if err_gb != nil {
		glog.Fatalf("Error parsing configmap name: %v", err_gb)
	}

	ipvsc.map1Lister.Store, ipvsc.map1Controller = cache.NewInformer(
		cache.NewListWatchFromClient(ipvsc.client.CoreV1().RESTClient(), "configmaps", cmns_svc,
			fields.OneTermEqualSelector(api.ObjectNameField, cmn_svc)),
		&apiv1.ConfigMap{}, resyncPeriod, mapEventHandler)

	ipvsc.map2Lister.Store, ipvsc.map2Controller = cache.NewInformer(
		cache.NewListWatchFromClient(ipvsc.client.CoreV1().RESTClient(), "configmaps", cmns_gb,
			fields.OneTermEqualSelector(api.ObjectNameField, cmn_gb)),
		&apiv1.ConfigMap{}, resyncPeriod, mapEventHandler)

	http.HandleFunc("/health", func(rw http.ResponseWriter, req *http.Request) {
		err := ipvsc.keepalived.Healthy()
		if err != nil {
			glog.Errorf("Health check unsuccessful: %v", err)
			http.Error(rw, fmt.Sprintf("keepalived not healthy: %v", err), 500)
			return
		}
		glog.V(3).Info("Health check successful")
		fmt.Fprint(rw, "OK")
	})

	http.HandleFunc("/metrics", func(rw http.ResponseWriter, req *http.Request) {
		metrics, err := ipvsc.keepalived.Metrics()
		if err != nil {
			glog.Errorf("Metrics API unsuccessful: %v", err)
			http.Error(rw, fmt.Sprintf("Metrics API error: %v", err), 500)
			return
		}
        jsOut ,jsErr := json.Marshal( metrics )
        if jsErr == nil{
            fmt.Fprint(rw, string(jsOut) )
        }else{
            fmt.Fprint(rw, "json.Marshal error %v\n" ,jsErr)
        }
	})


	return &ipvsc
}

func (ipvsc *ipvsControllerController) getConfigMap(ns, name string) (*apiv1.ConfigMap, error) {
	s1, exists1, err1 := ipvsc.map1Lister.Store.GetByKey(fmt.Sprintf("%v/%v", ns, name))
	s2, exists2, err2 := ipvsc.map2Lister.Store.GetByKey(fmt.Sprintf("%v/%v", ns, name))

	if err1 != nil {
		return nil, err1
	}

	if err2 != nil {
		return nil, err2
	}
	if !exists1 && !exists2  {
		return nil, fmt.Errorf("configmap %v/%v was not found",  ns, name)
	}
    if exists1 {
	    return s1.(*apiv1.ConfigMap), nil
    } else {
	    return s2.(*apiv1.ConfigMap), nil
    }
}

func checksum(filename string) (string, error) {
	var result []byte
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(result)), nil
}
