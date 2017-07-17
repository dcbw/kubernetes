// +build linux

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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"reflect"
	"testing"

	types020 "github.com/containernetworking/cni/pkg/types/020"
	"github.com/stretchr/testify/mock"
	"k8s.io/api/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	utiltesting "k8s.io/client-go/util/testing"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	containertest "k8s.io/kubernetes/pkg/kubelet/container/testing"
	"k8s.io/kubernetes/pkg/kubelet/network/cni/testing"
	"k8s.io/kubernetes/pkg/kubelet/network/hostport"
	networktest "k8s.io/kubernetes/pkg/kubelet/network/testing"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
)

func installTestPluginAndConfig(t *testing.T, testDir, plugType, netName string) (string, string, string, string, string) {
	confDir := path.Join(testDir, "etc", "cni", "net.d")
	binDir := path.Join(testDir, "opt", "cni", "bin")

	if netName != "" {
		if err := os.MkdirAll(confDir, 0777); err != nil {
			t.Fatalf("Failed to create plugin config dir %s: %v", confDir, err)
		}
		confFile := path.Join(confDir, netName+".conf")
		f, err := os.Create(confFile)
		if err != nil {
			t.Fatalf("Failed to install plugin %s: %v", confFile, err)
		}
		defer f.Close()

		networkConfig := fmt.Sprintf(`{ "name": "%s", "type": "%s", "capabilities": {"portMappings": true}  }`, netName, plugType)
		if _, err = f.WriteString(networkConfig); err != nil {
			t.Fatalf("Failed to write network config file %s: %v", confFile, err)
		}
	}

	if err := os.MkdirAll(binDir, 0777); err != nil {
		t.Fatalf("Failed to create plugin dir %s: %v", binDir, err)
	}
	binFile := path.Join(binDir, plugType)
	f, err := os.Create(binFile)
	if err != nil {
		t.Fatalf("Failed to create test plugin binary %s: %v", binFile, err)
	}
	defer f.Close()

	inputFile := path.Join(binDir, plugType+".in")
	outputFile := path.Join(binDir, plugType+".out")
	outputEnv := path.Join(binDir, plugType+".env")
	execScript := fmt.Sprintf(`#!/bin/bash
cat > %s
env > %s
echo "%%@" >> %s
export $(echo ${CNI_ARGS} | sed 's/;/ /g') &> /dev/null
mkdir -p %s &> /dev/null
echo -n "$CNI_COMMAND $CNI_NETNS $K8S_POD_NAMESPACE $K8S_POD_NAME $K8S_POD_INFRA_CONTAINER_ID" >& %s
echo -n "{ \"ip4\": { \"ip\": \"10.1.0.23/24\" } }"
`, inputFile, outputEnv, outputEnv, binDir, outputFile)
	if _, err = f.WriteString(execScript); err != nil {

		t.Fatalf("Failed to write plugin exec %s: %v", binFile, err)
	}
	if err := f.Chmod(0777); err != nil {
		t.Fatalf("Failed to set exec perms on %s: %v", binFile, err)
	}

	return confDir, binDir, inputFile, outputFile, outputEnv
}

func tearDownPlugin(tmpDir string) {
	if err := os.RemoveAll(tmpDir); err != nil {
		fmt.Printf("Error in cleaning up test: %v", err)
	}
}

func assertFileContents(t *testing.T, filePath, expectedContents string) {
	output, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Errorf("Failed to read output file %s: %v", filePath, err)
	}
	if expectedContents != "" && string(output) != expectedContents {
		t.Errorf("Mismatch in expected file %s output: expected %q, got %q", filePath, expectedContents, string(output))
	}
}

type fakeNetworkHost struct {
	networktest.FakePortMappingGetter
	kubeClient clientset.Interface
	runtime    kubecontainer.Runtime
}

func NewFakeHost(kubeClient clientset.Interface, pods []*containertest.FakePod, ports map[string][]*hostport.PortMapping) *fakeNetworkHost {
	host := &fakeNetworkHost{
		networktest.FakePortMappingGetter{PortMaps: ports},
		kubeClient,
		&containertest.FakeRuntime{
			AllPodList: pods,
		},
	}
	return host
}

func (fnh *fakeNetworkHost) GetPodByName(name, namespace string) (*v1.Pod, bool) {
	return nil, false
}

func (fnh *fakeNetworkHost) GetKubeClient() clientset.Interface {
	return fnh.kubeClient
}

func (fnh *fakeNetworkHost) GetRuntime() kubecontainer.Runtime {
	return fnh.runtime
}

func (fnh *fakeNetworkHost) GetNetNS(containerID string) (string, error) {
	return fnh.GetRuntime().GetNetNS(kubecontainer.ContainerID{Type: "test", ID: containerID})
}

func (fnh *fakeNetworkHost) SupportsLegacyFeatures() bool {
	return true
}

type fakeNetGetter struct {
	getFn func(string, string) (*KubeNetwork, error)
}

func (n *fakeNetGetter) GetNetwork(namespace, netName string) (*KubeNetwork, error) {
	return n.getFn(namespace, netName)
}

func TestCNIPlugin(t *testing.T) {
	podIP := "10.0.0.2"
	podIPOutput := fmt.Sprintf("4: eth0    inet %s/24 scope global dynamic eth0\\       valid_lft forever preferred_lft forever", podIP)
	fakeCmds := []utilexec.FakeCommandAction{
		func(cmd string, args ...string) utilexec.Cmd {
			return utilexec.InitFakeCmd(&utilexec.FakeCmd{
				CombinedOutputScript: []utilexec.FakeCombinedOutputAction{
					func() ([]byte, error) {
						return []byte(podIPOutput), nil
					},
				},
			}, cmd, args...)
		},
	}

	fexec := &utilexec.FakeExec{
		CommandScript: fakeCmds,
		LookPathFunc: func(file string) (string, error) {
			return fmt.Sprintf("/fake-bin/%s", file), nil
		},
	}

	// TODO mock for the test plugin too

	tmpDir := utiltesting.MkTmpdirOrDie("cni-test")
	defer tearDownPlugin(tmpDir)
	confDir, binDir, inputFile, outputFile, outputEnv := installTestPluginAndConfig(t, tmpDir, "test-plugin", "test-network")

	containerID := kubecontainer.ContainerID{Type: "test", ID: "test_infra_container"}
	pods := []*containertest.FakePod{{
		Pod: &kubecontainer.Pod{
			Containers: []*kubecontainer.Container{
				{ID: containerID},
			},
		},
		NetnsPath: "/proc/12345/ns/net",
	}}

	plugins := probeNetworkPluginsWithVendorCNIDirPrefix(confDir, binDir, "")
	if len(plugins) != 1 {
		t.Fatalf("Expected only one network plugin, got %d", len(plugins))
	}
	if plugins[0].Name() != "cni" {
		t.Fatalf("Expected CNI network plugin, got %q", plugins[0].Name())
	}

	cniPlugin, ok := plugins[0].(*cniNetworkPlugin)
	if !ok {
		t.Fatalf("Not a CNI network plugin!")
	}

	ports := map[string][]*hostport.PortMapping{
		containerID.ID: {
			{
				Name:          "name",
				HostPort:      8008,
				ContainerPort: 80,
				Protocol:      "UDP",
				HostIP:        "0.0.0.0",
			},
		},
	}
	fakeHost := NewFakeHost(nil, pods, ports)

	netGetter := &fakeNetGetter{
		getFn: func(namespace, name string) (*KubeNetwork, error) {
			return &KubeNetwork{Plugin: "foobar"}, nil
		},
	}
	if err := cniPlugin.internalInit(fakeHost, netGetter, fexec); err != nil {
		t.Fatalf("Failed to select the desired plugin: %v", err)
	}

	mockLoCNI := &mock_cni.MockCNI{}
	cniPlugin.networks.loNetwork.cniConfig = mockLoCNI
	mockLoCNI.On("AddNetworkList", cniPlugin.networks.loNetwork.netConfig, mock.AnythingOfType("*libcni.RuntimeConf")).Return(&types020.Result{IP4: &types020.IPConfig{IP: net.IPNet{IP: []byte{127, 0, 0, 1}}}}, nil)

	// Set up the pod
	if err := cniPlugin.SetUpPod("podNamespace", "podName", containerID, map[string]string{}); err != nil {
		t.Errorf("Expected nil: %v", err)
	}
	assertFileContents(t, outputEnv, "")
	assertFileContents(t, outputFile, "ADD /proc/12345/ns/net podNamespace podName test_infra_container")

	// Verify the correct network configuration was passed
	inputConfig := struct {
		RuntimeConfig struct {
			PortMappings []map[string]interface{} `json:"portMappings"`
		} `json:"runtimeConfig"`
	}{}
	inputBytes, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Errorf("failed to read CNI input config %s: %v", inputFile, err)
	}
	if err := json.Unmarshal(inputBytes, &inputConfig); err != nil {
		t.Errorf("failed to parse reported cni input config %s: %v", inputFile, err)
	}
	expectedMappings := []map[string]interface{}{
		// hah, golang always unmarshals unstructured json numbers as float64
		{"hostPort": 8008.0, "containerPort": 80.0, "protocol": "udp", "hostIP": "0.0.0.0"},
	}
	if !reflect.DeepEqual(inputConfig.RuntimeConfig.PortMappings, expectedMappings) {
		t.Errorf("mismatch in expected port mappings. expected %v got %v", expectedMappings, inputConfig.RuntimeConfig.PortMappings)
	}

	// Get its IP address
	status, err := cniPlugin.GetPodNetworkStatus("podNamespace", "podName", containerID)
	if err != nil {
		t.Errorf("Failed to read pod network status: %v", err)
	}
	if status.IP.String() != podIP {
		t.Errorf("Expected pod IP %q but got %q", podIP, status.IP.String())
	}

	// Tear it down
	if err := cniPlugin.TearDownPod("podNamespace", "podName", containerID); err != nil {
		t.Errorf("unexpected error on teardown: %v", err)
	}
	assertFileContents(t, outputFile, "DEL /proc/12345/ns/net podNamespace podName test_infra_container")

	mockLoCNI.AssertExpectations(t)
}

func TestMultiNetwork(t *testing.T) {
	tmpDir := utiltesting.MkTmpdirOrDie("cni-test")
	defer tearDownPlugin(tmpDir)
	confDir, binDir, _, p1OutputFile, p1OutputEnv := installTestPluginAndConfig(t, tmpDir, "test-plugin", "test-network")
	_, _, _, p2OutputFile, _ := installTestPluginAndConfig(t, tmpDir, "another-plugin", "another-network")
	_, _, _, p3OutputFile, _ := installTestPluginAndConfig(t, tmpDir, "noconfig-plugin", "")
	_, _, _, p4OutputFile, _ := installTestPluginAndConfig(t, tmpDir, "uncalled-plugin", "")

	containerID := kubecontainer.ContainerID{Type: "test", ID: "test_infra_container"}
	pods := []*containertest.FakePod{{
		Pod: &kubecontainer.Pod{
			Containers: []*kubecontainer.Container{
				{ID: containerID},
			},
		},
		NetnsPath: "/proc/12345/ns/net",
	}}

	plugins := probeNetworkPluginsWithVendorCNIDirPrefix(confDir, binDir, "")
	if len(plugins) != 1 || plugins[0].Name() != "cni" {
		t.Fatalf("Expected only the CNI network plugin, got %+v", plugins)
	}
	cniPlugin, ok := plugins[0].(*cniNetworkPlugin)
	if !ok {
		t.Fatalf("Not a CNI network plugin!")
	}

	fakeHost := NewFakeHost(nil, pods, make(map[string][]*hostport.PortMapping))

	netGetter := &fakeNetGetter{
		getFn: func(namespace, name string) (*KubeNetwork, error) {
			switch {
			case name == "another-network":
				return &KubeNetwork{}, nil
			case name == "test-network":
				return &KubeNetwork{}, nil
			case name == "other-network":
				return &KubeNetwork{Plugin: "noconfig-plugin"}, nil
			}
			return nil, fmt.Errorf("unexpected kube network %q", name)
		},
	}
	fexec := &utilexec.FakeExec{
 		LookPathFunc: func(file string) (string, error) {
			return fmt.Sprintf("/fake-bin/%s", file), nil
		},
	}
	if err := cniPlugin.internalInit(fakeHost, netGetter, fexec); err != nil {
		t.Fatalf("Failed to select the desired plugin: %v", err)
	}

	mockLoCNI := &mock_cni.MockCNI{}
	cniPlugin.networks.loNetwork.cniConfig = mockLoCNI
	mockLoCNI.On("AddNetworkList", cniPlugin.networks.loNetwork.netConfig, mock.AnythingOfType("*libcni.RuntimeConf")).Return(&types020.Result{IP4: &types020.IPConfig{IP: net.IPNet{IP: []byte{127, 0, 0, 1}}}}, nil)

	// Set up the pod
	netAnnotations := map[string]string{
		"alpha.network.k8s.io/networks": "another-network,test-network,other-network",
	}
	if err := cniPlugin.SetUpPod("podNamespace", "podName", containerID, netAnnotations); err != nil {
		t.Errorf("Expected nil: %v", err)
	}
	assertFileContents(t, p1OutputEnv, "")
	assertFileContents(t, p1OutputFile, "ADD /proc/12345/ns/net podNamespace podName test_infra_container")
	assertFileContents(t, p2OutputFile, "ADD /proc/12345/ns/net podNamespace podName test_infra_container")
	assertFileContents(t, p3OutputFile, "ADD /proc/12345/ns/net podNamespace podName test_infra_container")
	if _, err := os.Stat(p4OutputFile); err == nil {
		t.Fatalf("binary plugin %s was unexpectedly called", p4OutputFile)
	}

	// Tear it down
	if err := cniPlugin.TearDownPod("podNamespace", "podName", containerID); err != nil {
		t.Errorf("unexpected error on teardown: %v", err)
	}
	assertFileContents(t, p1OutputFile, "DEL /proc/12345/ns/net podNamespace podName test_infra_container")
	assertFileContents(t, p2OutputFile, "DEL /proc/12345/ns/net podNamespace podName test_infra_container")
	assertFileContents(t, p3OutputFile, "DEL /proc/12345/ns/net podNamespace podName test_infra_container")
	if _, err := os.Stat(p4OutputFile); err == nil {
		t.Fatalf("binary plugin %s was unexpectedly called", p4OutputFile)
	}

	mockLoCNI.AssertExpectations(t)
}
