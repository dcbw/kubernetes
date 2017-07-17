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
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	"sync"

	"github.com/containernetworking/cni/libcni"
	"github.com/golang/glog"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
)

const VendorCNIDirTemplate string = "%s/opt/%s/bin"

func vendorCNIDir(prefix, pluginType string) string {
	return fmt.Sprintf(VendorCNIDirTemplate, prefix, pluginType)
}

type cniNetwork struct {
	netName   string
	netConfig *libcni.NetworkConfigList
	cniConfig libcni.CNI

	// Pod-specific things filled in when the pod is added to the network
	podName      string
	podNamespace string
	podIfname    string
	podID        string
	capabilities map[string]interface{}
}

func newCNINetwork(name string, netConfig *libcni.NetworkConfigList, vendorPath, binDir string) *cniNetwork {
	path := []string{}
	if vendorPath != "" {
		path = append(path, vendorPath)
	}
	path = append(path, binDir)

	return &cniNetwork{
		netName:   name,
		netConfig: netConfig,
		cniConfig: &libcni.CNIConfig{Path: path},
	}
}

// Generate a copy of the network and it's configuration
func (n *cniNetwork) generatePodNetwork(netName, podNamespace, podName, podID string, capabilities map[string]interface{}) (*cniNetwork, error) {
	var err error
	if netName == "" {
		netName = n.netName
	}
	netConfig := n.netConfig
	if netConfig == nil {
		// If the network doesn't have config, it's a network for a plugin
		// binary and we need to generate config.  "name" should be the
		// network name, while "type" should be the plugin's on-disk binary
		// filename.
		// TODO: interrogate the plugin with the VERSION command when probing and
		// figure out a compatible version between its response and Kubernetes
		netConfig, err = libcni.ConfListFromBytes([]byte(fmt.Sprintf(`{
"cniVersion": "0.2.0",
"name": "%s",
"plugins":[{
  "type": "%s"
}]
}`, netName, n.netName)))
		if err != nil {
			return nil, fmt.Errorf("failed to generate cni plugin config for %q: %v", n.netName, err)
		}
	}

	podNet := &cniNetwork{}
	*podNet = *n
	podNet.netName = netName
	podNet.netConfig = netConfig
	podNet.podNamespace = podNamespace
	podNet.podName = podName
	podNet.podID = podID
	podNet.capabilities = capabilities
	return podNet, nil
}

func (n *cniNetwork) buildCNIRuntimeConf(netnsPath string) *libcni.RuntimeConf {
	glog.V(4).Infof("%s/%s using netns path %v and interface %q", n.podNamespace, n.podName, netnsPath, n.podIfname)
	rt := &libcni.RuntimeConf{
		ContainerID:    n.podID,
		NetNS:          netnsPath,
		IfName:         n.podIfname,
		CapabilityArgs: make(map[string]interface{}),
		Args: [][2]string{
			{"IgnoreUnknown", "1"},
			{"K8S_POD_NAMESPACE", n.podNamespace},
			{"K8S_POD_NAME", n.podName},
			{"K8S_POD_INFRA_CONTAINER_ID", n.podID},
		},
	}
	for k, v := range n.capabilities {
		rt.CapabilityArgs[k] = v
	}
	return rt
}

func (n *cniNetwork) addPod(netnsPath, ifname string) (cnitypes.Result, error) {
	n.podIfname = ifname
	glog.V(4).Infof("About to add CNI network %v (type=%v) to pod %s/%s (%s)", n.netConfig.Name, n.netConfig.Plugins[0].Network.Type, n.podNamespace, n.podName, n.podID)
	return n.cniConfig.AddNetworkList(n.netConfig, n.buildCNIRuntimeConf(netnsPath))
}

func (n *cniNetwork) removePod(netnsPath string) error {
	glog.V(4).Infof("About to del CNI network %v (type=%v) from pod %s/%s (%s)", n.netConfig.Name, n.netConfig.Plugins[0].Network.Type, n.podNamespace, n.podName, n.podID)
	return n.cniConfig.DelNetworkList(n.netConfig, n.buildCNIRuntimeConf(netnsPath))
}

type cniNetworks struct {
	sync.RWMutex
	defaultNetwork *cniNetwork
	loNetwork      *cniNetwork

	// Maps <json-name-or-plugin-name>::<network object> and contains only the *first*
	// alphabetically sorted network object for a given JSON name or plugin name.
	networks map[string]*cniNetwork

	// Track which networks are used by which pods, so that if the pod goes
	// away (eg, deleted from apiserver) we can still tear down the correct
	// networks without any annotations.
	// TODO: somehow handle kubelet restart by persisting this map
	pods map[string][]*cniNetwork

	pluginDir          string
	binDir             string
	vendorCNIDirPrefix string
	kubeNetGetter      NetworkGetter
}

func newCNINetworks(pluginDir, binDir, vendorCNIDirPrefix string, kubeNetGetter NetworkGetter) *cniNetworks {
	loConfig, err := libcni.ConfListFromBytes([]byte(`{
  "cniVersion": "0.2.0",
  "name": "cni-loopback",
  "plugins":[{
    "type": "loopback"
  }]
}`))
	if err != nil {
		// The hardcoded config above should always be valid and unit tests will
		// catch this
		panic(err)
	}
	loNetwork := newCNINetwork("lo", loConfig, vendorCNIDir(vendorCNIDirPrefix, "loopback"), binDir)

	return &cniNetworks{
		pluginDir:          pluginDir,
		binDir:             binDir,
		vendorCNIDirPrefix: vendorCNIDirPrefix,
		networks:           make(map[string]*cniNetwork),
		pods:               make(map[string][]*cniNetwork),
		loNetwork:          loNetwork,
		kubeNetGetter:      kubeNetGetter,
	}
}

// Returns a map of CNI networks, the "default" network, and an error
func getCNINetworks(pluginDir, binDir, vendorCNIDirPrefix string) (map[string]*cniNetwork, *cniNetwork, error) {
	files, err := libcni.ConfFiles(pluginDir, []string{".conf", ".conflist", ".json"})
	switch {
	case err != nil:
		return nil, nil, err
	case len(files) == 0:
		return nil, nil, fmt.Errorf("No networks found in %s", pluginDir)
	}

	// First grab networks conf configuration files
	var defaultNetwork *cniNetwork
	networks := make(map[string]*cniNetwork)
	sort.Strings(files)
	for _, confFile := range files {
		var confList *libcni.NetworkConfigList
		if strings.HasSuffix(confFile, ".conflist") {
			confList, err = libcni.ConfListFromFile(confFile)
			if err != nil {
				glog.Warningf("Error loading CNI config list file %s: %v", confFile, err)
				continue
			}
		} else {
			conf, err := libcni.ConfFromFile(confFile)
			if err != nil {
				glog.Warningf("Error loading CNI config file %s: %v", confFile, err)
				continue
			}
			confList, err = libcni.ConfListFromConf(conf)
			if err != nil {
				glog.Warningf("Error converting CNI config file %s to list: %v", confFile, err)
				continue
			}
		}
		if len(confList.Plugins) == 0 {
			glog.Warningf("CNI config list %s has no networks, skipping", confFile)
			continue
		}
		if _, ok := networks[confList.Name]; ok {
			glog.Warningf("CNI config list %s has duplicate name, skipping", confFile)
			continue
		}

		// Search for vendor-specific plugins as well as default plugins in the CNI codebase.
		confType := confList.Plugins[0].Network.Type
		network := newCNINetwork(confList.Name, confList, vendorCNIDir(vendorCNIDirPrefix, confType), binDir)
		networks[confList.Name] = network
		// Cache the first found network as the default
		if defaultNetwork == nil {
			defaultNetwork = network
		}
	}

	// Now create networks for plugins
	// TODO: somehow traverse vendor directories under VendorCNIDirTemplate/opt/*/bin
	if pluginFiles, err := ioutil.ReadDir(binDir); err == nil {
		for _, info := range pluginFiles {
			if info.IsDir() || (info.Mode()&0700) != 0700 {
				continue
			}
			if err != nil {
				glog.Warningf("failed to create cni config for %s/%s", binDir, info.Name())
				continue
			}

			if _, ok := networks[info.Name()]; ok {
				glog.Warningf("ignore duplicate cni config for %s/%s", binDir, info.Name())
				continue
			}

			networks[info.Name()] = newCNINetwork(info.Name(), nil, "", binDir)
		}
	}

	if len(networks) == 0 {
		return nil, nil, fmt.Errorf("No valid networks found in %s", pluginDir)
	}

	return networks, defaultNetwork, nil
}

func (cn *cniNetworks) syncNetworkConfig() {
	networks, defaultNetwork, err := getCNINetworks(cn.pluginDir, cn.binDir, cn.vendorCNIDirPrefix)
	if err != nil {
		// Errors loading networks are non-fatal; we just try again later
		glog.Warningf("Unable to load CNI configuration: %s", err)
		return
	}

	cn.Lock()
	defer cn.Unlock()
	cn.defaultNetwork = defaultNetwork
	cn.networks = networks
}

func (cn *cniNetworks) initialized() bool {
	cn.RLock()
	defer cn.RUnlock()
	return cn.defaultNetwork != nil
}

type KubeNetwork struct {
	Spec *KubeNetworkSpec `json:"spec,omitempty"`
}

type KubeNetworkSpec struct {
	Plugin string  `json:"plugin,omitempty"`
}

type NetworkGetter interface {
	GetNetwork(namespace, name string) (*KubeNetwork, error)
}

func (cn *cniNetworks) getNetworksByAnnotation(namespace, name, podID, networksAnnotation string, capabilities map[string]interface{}) ([]*cniNetwork, error) {
	cn.RLock()
	defer cn.RUnlock()

	if networksAnnotation == "" {
		net, err := cn.defaultNetwork.generatePodNetwork("", namespace, name, podID, capabilities)
		if err != nil {
			return nil, err
		}
		return []*cniNetwork{net}, nil
	}

	if cn.kubeNetGetter == nil {
		return nil, fmt.Errorf("multiple networks unsupported without a network getter")
	}

	networks := make([]*cniNetwork, 0)
	for _, netName := range strings.Split(networksAnnotation, ",") {
		kubeNetwork, err := cn.kubeNetGetter.GetNetwork(namespace, netName)
		if err != nil {
			return nil, err
		}
		if kubeNetwork.Spec == nil {
			return nil, fmt.Errorf("invalid kube network object %+v (missing spec)", kubeNetwork)
		}
		configName := kubeNetwork.Spec.Plugin
		if configName == "" {
			configName = netName
		}

		net, ok := cn.networks[configName]
		if !ok {
			return nil, fmt.Errorf("failed to find requested pod '%s/%s' network %q", namespace, name, configName)
		}

		podNet, err := net.generatePodNetwork(netName, namespace, name, podID, capabilities)
		if err != nil {
			return nil, fmt.Errorf("failed to generate cni plugin config for %q: %v", configName, err)
		}
		networks = append(networks, podNet)
	}

	return networks, nil
}

func (cn *cniNetworks) SetUpPod(namespace, name, id string, netnsPath string, netAnnotation string, capabilities map[string]interface{}) (cnitypes.Result, error) {
	networks, err := cn.getNetworksByAnnotation(namespace, name, id, netAnnotation, capabilities)
	if err != nil {
		return nil, err
	}

	loNet, err := cn.loNetwork.generatePodNetwork("", namespace, name, id, capabilities)
	if err != nil {
		return nil, err
	}
	if _, err = loNet.addPod(netnsPath, "lo"); err != nil {
		return nil, err
	}

	var firstResult cnitypes.Result
	for i, net := range networks {
		ifname := fmt.Sprintf("eth%d", i)
		res, err := net.addPod(netnsPath, ifname)
		if err != nil {
			return nil, err
		}
		if firstResult == nil {
			firstResult = res
		}
	}

	cn.Lock()
	defer cn.Unlock()
	cn.pods[id] = networks

	return firstResult, nil
}

func (cn *cniNetworks) getPodNetworks(id string) ([]*cniNetwork) {
	cn.RLock()
	defer cn.RUnlock()
	return cn.pods[id]
}

func (cn *cniNetworks) TearDownPod(id, netnsPath string) error {
	errList := []error{}
	for _, net := range cn.getPodNetworks(id) {
		if err := net.removePod(netnsPath); err != nil {
			errList = append(errList, err)
		}
	}

	cn.Lock()
	defer cn.Unlock()
	delete(cn.pods, id)

	return kerrors.NewAggregate(errList)
}
