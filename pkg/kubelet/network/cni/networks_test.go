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
	"os"
	"path"
	"testing"

	utiltesting "k8s.io/client-go/util/testing"
)

func deleteTempdir(tmpDir string) {
	err := os.RemoveAll(tmpDir)
	if err != nil {
		fmt.Printf("Error in cleaning up test: %v", err)
	}
}

type tmpNet struct {
	Name string `json:"name"`
}

func writeConfFile(t *testing.T, dir, filename, data string) string {
	filePath := path.Join(dir, filename)
	if err := ioutil.WriteFile(filePath, []byte(data), 0644); err != nil {
		t.Fatalf("failed to write CNI config %q: %v", filePath, err)
	}
	n := &tmpNet{}
	if err := json.Unmarshal([]byte(data), &n); err != nil {
		t.Fatalf("failed to unmarshal CNI config %q: %v", data, err)
	}
	return n.Name
}

func createBinPlugin(t *testing.T, dir, filename string) {
	filePath := path.Join(dir, filename)
	if err := ioutil.WriteFile(filePath, []byte("blahblahblah"), 0755); err != nil {
		t.Fatalf("failed to write CNI plugin %q: %v", filePath, err)
	}
}

func TestSyncNetworks(t *testing.T) {
	confTmpDir := utiltesting.MkTmpdirOrDie("cni-configs-test")
	defer deleteTempdir(confTmpDir)

	confNames := []string{
		writeConfFile(t, confTmpDir, "30-foobar.conf", `{
  "cniVersion": "0.2.0",
  "name": "foobar",
  "plugins":[{
    "type": "loopback"
  }]
}`),
		writeConfFile(t, confTmpDir, "20-blah.conf", `{
  "cniVersion": "0.2.0",
  "name": "blah",
  "plugins":[{
    "type": "loopback"
  }]
}`),
		writeConfFile(t, confTmpDir, "10-bar.conf", `{
  "cniVersion": "0.2.0",
  "name": "bar",
  "plugins":[{
    "type": "loopback"
  }]
}`),
	}

	binTmpDir := utiltesting.MkTmpdirOrDie("cni-bins-test")
	defer deleteTempdir(binTmpDir)

	createBinPlugin(t, binTmpDir, "awesome-plugin")
	// Add a plugin with the same name as a config network; should be ignored
	createBinPlugin(t, binTmpDir, "bar")

	nets := newCNINetworks(confTmpDir, binTmpDir, "", nil)
	nets.syncNetworkConfig()

	// Ensure we have the right networks
	if len(nets.networks) != 4 {
		t.Fatalf("expected 4 networks, found %d", len(nets.networks))
	}
	for _, name := range confNames {
		net, ok := nets.networks[name]
		if !ok {
			t.Fatalf("expected network %q but didn't find it", name)
		}
		if net.netConfig == nil {
			t.Fatalf("unexpected empty netConfig for network %q", name)
		}
	}

	// Now test the binary generated network config
	net, ok := nets.networks["awesome-plugin"]
	if !ok {
		t.Fatalf("expected binary plugin network 'awesome-plugin' but didn't find it")
	}
	if net.netConfig != nil {
		t.Fatalf("unexpected netConfig for 'awesome-plugin'")
	}

	// Ensure the default network is the first one found alphabetically
	if nets.defaultNetwork == nil {
		t.Fatalf("unexpected nil default network")
	}
	if nets.defaultNetwork.netName != "bar" {
		t.Fatalf("expected default network 'bar' but got %q", nets.defaultNetwork.netName)
	}

	// Make a bunch of changes
	filePath := path.Join(confTmpDir, "10-bar.conf")
	if err := os.Remove(filePath); err != nil {
		t.Fatalf("failed to remove config %q: %v", filePath, err)
	}

	writeConfFile(t, confTmpDir, "20-blah.conf", `{
  "cniVersion": "0.2.0",
  "name": "blah",
  "plugins":[{
    "type": "host-local"
  }]
}`)

	filePath = path.Join(binTmpDir, "awesome-plugin")
	if err := os.Remove(filePath); err != nil {
		t.Fatalf("failed to remove bin plugin %q: %v", filePath, err)
	}

	createBinPlugin(t, binTmpDir, "great-plugin")
	createBinPlugin(t, binTmpDir, "dumb-plugin")

	nets.syncNetworkConfig()
	if len(nets.networks) != 5 {
		t.Fatalf("expected 5 networks, found %d", len(nets.networks))
	}
	for _, name := range []string{"foobar", "blah"} {
		net, ok := nets.networks[name]
		if !ok {
			t.Fatalf("expected network %q but didn't find it", name)
		}
		if net.netConfig == nil {
			t.Fatalf("unexpected empty netConfig for network %q", name)
		}
	}

	for _, name := range []string{"bar", "great-plugin", "dumb-plugin"} {
		net, ok := nets.networks[name]
		if !ok {
			t.Fatalf("expected binary plugin network %q but didn't find it", name)
		}
		if net.netConfig != nil {
			t.Fatalf("unexpected netConfig for %q", name)
		}
	}

	// Ensure the default network changed
	if nets.defaultNetwork == nil {
		t.Fatalf("unexpected nil default network")
	}
	if nets.defaultNetwork.netName != "blah" {
		t.Fatalf("expected default network 'blah' but got %q", nets.defaultNetwork.netName)
	}
}

type netTestNetGetter struct {}

func (n *netTestNetGetter) GetNetwork(namespace, netName string) (*KubeNetwork, error) {
	switch {
	case netName == "foobar":
		return &KubeNetwork{}, nil
	case netName == "something":
		return &KubeNetwork{}, nil
	case netName == "another-thing":
		return &KubeNetwork{
			Plugin: "great-plugin",
		}, nil
	}
	return nil, fmt.Errorf("failed to find network %q", netName)
}

func TestGetNetworksByAnnotations(t *testing.T) {
	confTmpDir := utiltesting.MkTmpdirOrDie("cni-configs-test")
	defer deleteTempdir(confTmpDir)

	writeConfFile(t, confTmpDir, "30-foobar.conf", `{
  "cniVersion": "0.2.0",
  "name": "foobar",
  "plugins":[{
    "type": "loopback"
  }]
}`)
	writeConfFile(t, confTmpDir, "10-something.conf", `{
  "cniVersion": "0.2.0",
  "name": "something",
  "plugins":[{
    "type": "loopback"
  }]
}`)

	binTmpDir := utiltesting.MkTmpdirOrDie("cni-bins-test")
	defer deleteTempdir(binTmpDir)
	createBinPlugin(t, binTmpDir, "great-plugin")

	nets := newCNINetworks(confTmpDir, binTmpDir, "", &netTestNetGetter{})
	nets.syncNetworkConfig()

	netAnnotation := "foobar,something,another-thing"
	networks, err := nets.getNetworksByAnnotation("default", "some-pod", "blahblahblah", netAnnotation, make(map[string]interface{}))
	if err != nil {
		t.Fatalf("unexpected error getting networks from annotations: %v", err)
	}
	if len(networks) != 3 {
		t.Fatalf("expected 3 networks from annotations, got %d", len(networks))
	}
	for i, name := range []string{"foobar", "something", "another-thing"} {
		if networks[i].netName != name {
			t.Fatalf("unexpected network %v from annotation", networks[i])
		}
		if name == "else" {
			// make sure the network name is "another-thing" but the
			// type is the on-disk plugin filename (eg, "great-plugin")
			netConf := networks[i].netConfig
			if netConf.Name != "another-thing" {
				t.Fatalf("unexpected binary plugin network name %q", netConf.Name)
			}
			if len(netConf.Plugins) != 1 {
				t.Fatalf("unexpected binary plugin network configs len %d", len(netConf.Plugins))
			}
			if netConf.Plugins[0].Network.Name != "another-thing" {
				t.Fatalf("unexpected binary plugin network config name %q", netConf.Plugins[0].Network.Name)
			}
			if netConf.Plugins[0].Network.Type != "great-plugin" {
				t.Fatalf("unexpected binary plugin network config type %q", netConf.Plugins[0].Network.Type)
			}
		}
	}
}

func TestLoNetNonNil(t *testing.T) {
	confTmpDir := utiltesting.MkTmpdirOrDie("cni-configs-test")
	defer deleteTempdir(confTmpDir)
	binTmpDir := utiltesting.MkTmpdirOrDie("cni-bins-test")
	defer deleteTempdir(binTmpDir)
	nets := newCNINetworks(confTmpDir, binTmpDir, "", nil)
	if nets.loNetwork == nil || nets.loNetwork.netConfig == nil {
		t.Error("Expected non-nil lo network")
	}
}

func TestDefaultNetwork(t *testing.T) {
	confTmpDir := utiltesting.MkTmpdirOrDie("cni-configs-test")
	defer deleteTempdir(confTmpDir)

	writeConfFile(t, confTmpDir, "30-foobar.conf", `{
  "cniVersion": "0.2.0",
  "name": "foobar",
  "plugins":[{
    "type": "loopback"
  }]
}`)

	writeConfFile(t, confTmpDir, "40-baz.conf", `{
  "cniVersion": "0.2.0",
  "name": "baz",
  "plugins":[{
    "type": "loopback"
  }]
}`)

	binTmpDir := utiltesting.MkTmpdirOrDie("cni-bins-test")
	defer deleteTempdir(binTmpDir)

	nets := newCNINetworks(confTmpDir, binTmpDir, "", nil)
	nets.syncNetworkConfig()

	// Ensure the default network is the first one found alphabetically
	if nets.defaultNetwork == nil {
		t.Fatalf("unexpected nil default network")
	}
	if nets.defaultNetwork.netName != "foobar" {
		t.Fatalf("expected default network 'foo' but got %q", nets.defaultNetwork.netName)
	}

	networks, err := nets.getNetworksByAnnotation("default", "some-pod", "blahblahblah", "", make(map[string]interface{}))
	if err != nil {
		t.Fatalf("unexpected error getting networks from annotations: %v", err)
	}
	if len(networks) != 1 {
		t.Fatalf("expected 3 networks from annotations, got %d", len(networks))
	}
	if networks[0].netName != "foobar" {
		t.Fatalf("expected pod to use default network 'foobar' but got %q", networks[0].netName)
	}
}
