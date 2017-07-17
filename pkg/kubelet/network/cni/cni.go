/*
Copyright 2014 The Kubernetes Authors.

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

package cni

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/apis/componentconfig"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/network"
	utilexec "k8s.io/kubernetes/pkg/util/exec"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	CNIPluginName        = "cni"
	DefaultNetDir        = "/etc/cni/net.d"
	DefaultCNIDir        = "/opt/cni/bin"
)

type cniNetworkPlugin struct {
	network.NoopNetworkPlugin

	networks *cniNetworks

	host               network.Host
	execer             utilexec.Interface
	nsenterPath        string
	pluginDir          string
	binDir             string
	vendorCNIDirPrefix string

	kubeNetGetter      NetworkGetter
}

// cniPortMapping maps to the standard CNI portmapping Capability
// see: https://github.com/containernetworking/cni/blob/master/CONVENTIONS.md
type cniPortMapping struct {
	HostPort      int32  `json:"hostPort"`
	ContainerPort int32  `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIP"`
}

type liveNetGetter struct {
	client *kubernetes.Clientset
}

func newLiveNetGetter(kubeConfigPath string) (*liveNetGetter, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("cni unable to read kubeconfig %q: %v", kubeConfigPath, err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("cni unable to create kubernetes client with config %q: %v", kubeConfigPath, err)
	}
	return &liveNetGetter{client: client}, nil
}

func (l *liveNetGetter) GetNetwork(namespace, networkName string) (*KubeNetwork, error) {
	if l.client == nil {
		return nil, fmt.Errorf("failed to get network from apiserver: no kube client")
	}

	netPath := fmt.Sprintf("/apis/alpha.network.k8s.io/v1/namespaces/%s/networks/%s", namespace, networkName)
	networkJSON, err := l.client.ExtensionsV1beta1().RESTClient().Get().AbsPath(netPath).DoRaw()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve network %q at path %q: %v", networkName, netPath, err)
	}
	kubeNetwork := &KubeNetwork{}
	if err := json.Unmarshal(networkJSON, &kubeNetwork); err != nil {
		return nil, fmt.Errorf("failed to parse network %q data %q: %v", networkName, string(networkJSON), err)
	}

	return kubeNetwork, nil
}

func probeNetworkPluginsWithVendorCNIDirPrefix(pluginDir, binDir, vendorCNIDirPrefix string) []network.NetworkPlugin {
	if binDir == "" {
		binDir = DefaultCNIDir
	}
	if pluginDir == "" {
		pluginDir = DefaultNetDir
	}

	plugin := &cniNetworkPlugin{
		pluginDir:          pluginDir,
		binDir:             binDir,
		vendorCNIDirPrefix: vendorCNIDirPrefix,
	}

	return []network.NetworkPlugin{plugin}
}

func ProbeNetworkPlugins(pluginDir, binDir string) []network.NetworkPlugin {
	return probeNetworkPluginsWithVendorCNIDirPrefix(pluginDir, binDir, "")
}

func (plugin *cniNetworkPlugin) internalInit(host network.Host, kubeNetGetter NetworkGetter, execer utilexec.Interface) error {
	var err error
	plugin.nsenterPath, err = execer.LookPath("nsenter")
	if err != nil {
		return err
	}
	plugin.host = host
	plugin.execer = execer
	plugin.networks = newCNINetworks(plugin.pluginDir, plugin.binDir, plugin.vendorCNIDirPrefix, kubeNetGetter)
	plugin.networks.syncNetworkConfig()

	return nil
}

func (plugin *cniNetworkPlugin) Init(host network.Host, hairpinMode componentconfig.HairpinMode, nonMasqueradeCIDR string, mtu int, kubeConfig string) error {
	var netGetter *liveNetGetter
	var err error
	if kubeConfig != "" {
		netGetter, err = newLiveNetGetter(kubeConfig)
		if err != nil {
			return err
		}
	}
	return plugin.internalInit(host, netGetter, utilexec.New())
}

func (plugin *cniNetworkPlugin) checkInitialized() error {
	if !plugin.networks.initialized() {
		return errors.New("cni config uninitialized")
	}
	return nil
}

func (plugin *cniNetworkPlugin) Name() string {
	return CNIPluginName
}

func (plugin *cniNetworkPlugin) Status() error {
	// sync network config from pluginDir periodically to detect network config updates
	plugin.networks.syncNetworkConfig()

	// Can't set up pods if we don't have any CNI network configs yet
	return plugin.checkInitialized()
}

func (plugin *cniNetworkPlugin) SetUpPod(namespace string, name string, id kubecontainer.ContainerID, annotations map[string]string) error {
	if err := plugin.checkInitialized(); err != nil {
		return err
	}
	netnsPath, err := plugin.host.GetNetNS(id.ID)
	if err != nil {
		return fmt.Errorf("CNI failed to retrieve network namespace path: %v", err)
	}

	capabilities, err := plugin.buildPodCNICapabilities(id)
	if err != nil {
		return err
	}

	netAnnotation := annotations["alpha.network.k8s.io/networks"]
	_, err = plugin.networks.SetUpPod(namespace, name, id.ID, netnsPath, netAnnotation, capabilities)
	return err
}

func (plugin *cniNetworkPlugin) TearDownPod(namespace string, name string, id kubecontainer.ContainerID) error {
	// Lack of netns path should not be fatal on teardown
	netnsPath, err := plugin.host.GetNetNS(id.ID)
	if err != nil {
		glog.Warningf("CNI failed to retrieve network namespace path: %v", err)
	}

	return plugin.networks.TearDownPod(id.ID, netnsPath)
}

// TODO: Use the addToNetwork function to obtain the IP of the Pod. That will assume idempotent ADD call to the plugin.
// Also fix the runtime's call to Status function to be done only in the case that the IP is lost, no need to do periodic calls
func (plugin *cniNetworkPlugin) GetPodNetworkStatus(namespace string, name string, id kubecontainer.ContainerID) (*network.PodNetworkStatus, error) {
	netnsPath, err := plugin.host.GetNetNS(id.ID)
	if err != nil {
		return nil, fmt.Errorf("CNI failed to retrieve network namespace path: %v", err)
	}
	if netnsPath == "" {
		return nil, fmt.Errorf("Cannot find the network namespace, skipping pod network status for container %q", id)
	}

	ip, err := network.GetPodIP(plugin.execer, plugin.nsenterPath, netnsPath, network.DefaultInterfaceName)
	if err != nil {
		return nil, err
	}

	return &network.PodNetworkStatus{IP: ip}, nil
}

func (plugin *cniNetworkPlugin) buildPodCNICapabilities(podInfraContainerID kubecontainer.ContainerID) (map[string]interface{}, error) {
	// port mappings are a cni capability-based args, rather than parameters
	// to a specific plugin
	portMappings, err := plugin.host.GetPodPortMappings(podInfraContainerID.ID)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve port mappings: %v", err)
	}
	portMappingsParam := make([]cniPortMapping, 0, len(portMappings))
	for _, p := range portMappings {
		if p.HostPort <= 0 {
			continue
		}
		portMappingsParam = append(portMappingsParam, cniPortMapping{
			HostPort:      p.HostPort,
			ContainerPort: p.ContainerPort,
			Protocol:      strings.ToLower(string(p.Protocol)),
			HostIP:        p.HostIP,
		})
	}
	return map[string]interface{}{
		"portMappings": portMappingsParam,
	}, nil
}
