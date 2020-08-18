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

package userspace

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/pkg/proxy"
	ipttest "k8s.io/kubernetes/pkg/util/iptables/testing"
	"k8s.io/utils/exec"
	fakeexec "k8s.io/utils/exec/testing"
)

const (
	udpIdleTimeoutForTest = 250 * time.Millisecond
)

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

func waitForClosedPortTCP(p *Proxier, proxyPort int) error {
	for i := 0; i < 50; i++ {
		conn, err := net.Dial("tcp", joinHostPort("", proxyPort))
		if err != nil {
			return nil
		}
		conn.Close()
		time.Sleep(1 * time.Millisecond)
	}
	return fmt.Errorf("port %d still open", proxyPort)
}

func waitForClosedPortUDP(p *Proxier, proxyPort int) error {
	for i := 0; i < 50; i++ {
		conn, err := net.Dial("udp", joinHostPort("", proxyPort))
		if err != nil {
			return nil
		}
		conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		// To detect a closed UDP port write, then read.
		_, err = conn.Write([]byte("x"))
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Timeout() {
				return nil
			}
		}
		var buf [4]byte
		_, err = conn.Read(buf[0:])
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Timeout() {
				return nil
			}
		}
		conn.Close()
		time.Sleep(1 * time.Millisecond)
	}
	return fmt.Errorf("port %d still open", proxyPort)
}

func waitForServiceInfo(t *testing.T, p *Proxier, servicePortName proxy.ServicePortName, service *v1.Service, idx int) *ServiceInfo {
	var svcInfo *ServiceInfo
	var exists bool
	wait.PollImmediate(50*time.Millisecond, 3*time.Second, func() (bool, error) {
		svcInfo, exists = p.getServiceInfo(servicePortName)
		return exists, nil
	})
	if !exists {
		t.Fatalf("can't find serviceInfo for %s", servicePortName)
	}
	if !svcInfo.IsAlive() {
		t.Fatalf("expected IsAlive() true for %s", servicePortName)
	}
	if svcInfo.portal.ip.String() != service.Spec.ClusterIP || int32(svcInfo.portal.port) != service.Spec.Ports[idx].Port || svcInfo.protocol != service.Spec.Ports[idx].Protocol {
		t.Errorf("unexpected serviceInfo for %s: %#v", servicePortName, svcInfo)
	}
	svcInfo.started.Wait()
	return svcInfo
}

func addServiceAndWaitForInfoIndex(t *testing.T, p *Proxier, servicePortName proxy.ServicePortName, service *v1.Service, idx int) *ServiceInfo {
	p.OnServiceAdd(service)
	return waitForServiceInfo(t, p, servicePortName, service, idx)
}

func addServiceAndWaitForInfo(t *testing.T, p *Proxier, servicePortName proxy.ServicePortName, service *v1.Service) *ServiceInfo {
	return addServiceAndWaitForInfoIndex(t, p, servicePortName, service, 0)
}

func waitForServiceDelete(t *testing.T, p *Proxier, svcInfo *ServiceInfo, service *v1.Service, waitFunc func(*Proxier, int) error) {
	p.OnServiceDelete(service)
	// Wait for the port to really close.
	if err := waitFunc(p, svcInfo.proxyPort); err != nil {
		t.Fatalf(err.Error())
	}
	svcInfo.finished.Wait()
	if svcInfo.IsAlive() {
		t.Fatalf("wrong value for IsAlive(): expected false")
	}
}

// udpEchoServer is a simple echo server in UDP, intended for testing the proxy.
type udpEchoServer struct {
	net.PacketConn
}

func newUDPEchoServer() (*udpEchoServer, error) {
	packetconn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	return &udpEchoServer{packetconn}, nil
}

func (r *udpEchoServer) Loop() {
	var buffer [4096]byte
	for {
		n, cliAddr, err := r.ReadFrom(buffer[0:])
		if err != nil {
			fmt.Printf("ReadFrom failed: %v\n", err)
			continue
		}
		r.WriteTo(buffer[0:n], cliAddr)
	}
}

var tcpServerPort int32
var udpServerPort int32

func TestMain(m *testing.M) {
	// Don't handle panics
	runtime.ReallyCrash = true

	// TCP setup.
	tcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(r.URL.Path[1:]))
	}))
	defer tcp.Close()

	u, err := url.Parse(tcp.URL)
	if err != nil {
		panic(fmt.Sprintf("failed to parse: %v", err))
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		panic(fmt.Sprintf("failed to parse: %v", err))
	}
	tcpServerPortValue, err := strconv.Atoi(port)
	if err != nil {
		panic(fmt.Sprintf("failed to atoi(%s): %v", port, err))
	}
	tcpServerPort = int32(tcpServerPortValue)

	// UDP setup.
	udp, err := newUDPEchoServer()
	if err != nil {
		panic(fmt.Sprintf("failed to make a UDP server: %v", err))
	}
	_, port, err = net.SplitHostPort(udp.LocalAddr().String())
	if err != nil {
		panic(fmt.Sprintf("failed to parse: %v", err))
	}
	udpServerPortValue, err := strconv.Atoi(port)
	if err != nil {
		panic(fmt.Sprintf("failed to atoi(%s): %v", port, err))
	}
	udpServerPort = int32(udpServerPortValue)
	go udp.Loop()

	ret := m.Run()
	// it should be safe to call Close() multiple times.
	tcp.Close()
	os.Exit(ret)
}

func testEchoTCP(t *testing.T, address string, port int) {
	path := "aaaaa"
	res, err := http.Get("http://" + address + ":" + fmt.Sprintf("%d", port) + "/" + path)
	if err != nil {
		t.Fatalf("error connecting to server: %v", err)
	}
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("error reading data: %v %v", err, string(data))
	}
	if string(data) != path {
		t.Errorf("expected: %s, got %s", path, string(data))
	}
}

func testEchoUDP(t *testing.T, address string, port int) {
	data := "abc123"

	conn, err := net.Dial("udp", joinHostPort(address, port))
	if err != nil {
		t.Fatalf("error connecting to server: %v", err)
	}
	if _, err := conn.Write([]byte(data)); err != nil {
		t.Fatalf("error sending to server: %v", err)
	}
	var resp [1024]byte
	n, err := conn.Read(resp[0:])
	if err != nil {
		t.Errorf("error receiving data: %v", err)
	}
	if string(resp[0:n]) != data {
		t.Errorf("expected: %s, got %s", data, string(resp[0:n]))
	}
}

func waitForNumProxyClients(t *testing.T, s *ServiceInfo, want int, timeout time.Duration) {
	var got int
	now := time.Now()
	deadline := now.Add(timeout)
	for time.Now().Before(deadline) {
		s.ActiveClients.Mu.Lock()
		got = len(s.ActiveClients.Clients)
		s.ActiveClients.Mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Errorf("expected %d ProxyClients live, got %d", want, got)
}

func startProxier(p *Proxier, t *testing.T) {
	go func() {
		p.SyncLoop()
	}()
	p.OnServiceSynced()
	p.OnEndpointsSynced()
}

func TestTCPProxy(t *testing.T) {
	lb := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: tcpServerPort}},
		}},
	})

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	svcInfo := addServiceAndWaitForInfo(t, p, service, &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     80,
			Protocol: "TCP",
		}}},
	})
	testEchoTCP(t, "127.0.0.1", svcInfo.proxyPort)
}

func TestUDPProxy(t *testing.T) {
	lb := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: udpServerPort}},
		}},
	})

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	svcInfo := addServiceAndWaitForInfo(t, p, service, &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     80,
			Protocol: "UDP",
		}}},
	})
	testEchoUDP(t, "127.0.0.1", svcInfo.proxyPort)
}

func TestUDPProxyTimeout(t *testing.T) {
	lb := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: udpServerPort}},
		}},
	})

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	svcInfo := addServiceAndWaitForInfo(t, p, service, &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     80,
			Protocol: "UDP",
		}}},
	})
	testEchoUDP(t, "127.0.0.1", svcInfo.proxyPort)
	// When connecting to a UDP service endpoint, there should be a Conn for proxy.
	waitForNumProxyClients(t, svcInfo, 1, time.Second)
	// If conn has no activity for serviceInfo.timeout since last Read/Write, it should be closed because of timeout.
	waitForNumProxyClients(t, svcInfo, 0, 2*time.Second)
}

func TestMultiPortProxy(t *testing.T) {
	lb := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo-p"}, Port: "p"}
	serviceQ := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo-q"}, Port: "q"}
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Protocol: "TCP", Port: tcpServerPort}},
		}},
	})
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: serviceQ.Name, Namespace: serviceQ.Namespace},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "q", Protocol: "UDP", Port: udpServerPort}},
		}},
	})

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	svcInfo := addServiceAndWaitForInfo(t, p, serviceP, &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     80,
			Protocol: "TCP",
		}}},
	})
	testEchoTCP(t, "127.0.0.1", svcInfo.proxyPort)

	svcInfo = addServiceAndWaitForInfo(t, p, serviceQ, &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceQ.Name, Namespace: serviceQ.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "q",
			Port:     80,
			Protocol: "UDP",
		}}},
	})
	testEchoUDP(t, "127.0.0.1", svcInfo.proxyPort)
}

func TestMultiPortOnServiceAdd(t *testing.T) {
	lb := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	serviceQ := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "q"}
	serviceX := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "x"}

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     80,
			Protocol: "TCP",
		}, {
			Name:     "q",
			Port:     81,
			Protocol: "UDP",
		}}},
	}

	// ports p and q should exist
	_ = addServiceAndWaitForInfo(t, p, serviceP, service)
	_ = waitForServiceInfo(t, p, serviceQ, service, 1)
	// non-existent port x should not exist
	svcInfo, exists := p.getServiceInfo(serviceX)
	if exists {
		t.Fatalf("found unwanted serviceInfo for %s: %#v", serviceX, svcInfo)
	}
}

func TestTCPProxyStop(t *testing.T) {
	lb := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Namespace: serviceP.Namespace, Name: serviceP.Name},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: tcpServerPort}},
		}},
	})

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     80,
			Protocol: "TCP",
		}}},
	}
	svcInfo := addServiceAndWaitForInfo(t, p, serviceP, service)
	conn, err := net.Dial("tcp", joinHostPort("", svcInfo.proxyPort))
	if err != nil {
		t.Fatalf("error connecting to proxy: %v", err)
	}
	conn.Close()

	// Wait for the port to really close.
	waitForServiceDelete(t, p, svcInfo, service, waitForClosedPortTCP)
}

func TestUDPProxyStop(t *testing.T) {
	lb := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Namespace: serviceP.Namespace, Name: serviceP.Name},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: udpServerPort}},
		}},
	})

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     80,
			Protocol: "UDP",
		}}},
	}
	svcInfo := addServiceAndWaitForInfo(t, p, serviceP, service)
	conn, err := net.Dial("udp", joinHostPort("", svcInfo.proxyPort))
	if err != nil {
		t.Fatalf("error connecting to proxy: %v", err)
	}
	conn.Close()

	// Wait for the port to really close.
	waitForServiceDelete(t, p, svcInfo, service, waitForClosedPortUDP)
}

func TestTCPProxyUpdateDelete(t *testing.T) {
	lb := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Namespace: serviceP.Namespace, Name: serviceP.Name},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: tcpServerPort}},
		}},
	})

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     9997,
			Protocol: "TCP",
		}}},
	}

	svcInfo := addServiceAndWaitForInfo(t, p, serviceP, service)
	conn, err := net.Dial("tcp", joinHostPort("", svcInfo.proxyPort))
	if err != nil {
		t.Fatalf("error connecting to proxy: %v", err)
	}
	conn.Close()

	// Wait for the port to really close.
	waitForServiceDelete(t, p, svcInfo, service, waitForClosedPortTCP)
}

func TestUDPProxyUpdateDelete(t *testing.T) {
	lb := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Namespace: serviceP.Namespace, Name: serviceP.Name},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: udpServerPort}},
		}},
	})

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     9997,
			Protocol: "UDP",
		}}},
	}

	svcInfo := addServiceAndWaitForInfo(t, p, serviceP, service)
	conn, err := net.Dial("udp", joinHostPort("", svcInfo.proxyPort))
	if err != nil {
		t.Fatalf("error connecting to proxy: %v", err)
	}
	conn.Close()

	// Wait for the port to really close.
	waitForServiceDelete(t, p, svcInfo, service, waitForClosedPortUDP)
}

func TestTCPProxyUpdateDeleteUpdate(t *testing.T) {
	lb := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	endpoint := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: tcpServerPort}},
		}},
	}
	lb.OnEndpointsAdd(endpoint)

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     9997,
			Protocol: "TCP",
		}}},
	}

	svcInfo := addServiceAndWaitForInfo(t, p, serviceP, service)
	conn, err := net.Dial("tcp", joinHostPort("", svcInfo.proxyPort))
	if err != nil {
		t.Fatalf("error connecting to proxy: %v", err)
	}
	conn.Close()

	// Wait for the port to really close.
	waitForServiceDelete(t, p, svcInfo, service, waitForClosedPortTCP)

	// need to add endpoint here because it got clean up during service delete
	lb.OnEndpointsAdd(endpoint)
	svcInfo = addServiceAndWaitForInfo(t, p, serviceP, service)
	testEchoTCP(t, "127.0.0.1", svcInfo.proxyPort)
}

func TestUDPProxyUpdateDeleteUpdate(t *testing.T) {
	lb := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	endpoint := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: udpServerPort}},
		}},
	}
	lb.OnEndpointsAdd(endpoint)

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     9997,
			Protocol: "UDP",
		}}},
	}

	svcInfo := addServiceAndWaitForInfo(t, p, serviceP, service)
	conn, err := net.Dial("udp", joinHostPort("", svcInfo.proxyPort))
	if err != nil {
		t.Fatalf("error connecting to proxy: %v", err)
	}
	conn.Close()

	// Wait for the port to really close.
	waitForServiceDelete(t, p, svcInfo, service, waitForClosedPortUDP)

	// need to add endpoint here because it got clean up during service delete
	lb.OnEndpointsAdd(endpoint)
	svcInfo = addServiceAndWaitForInfo(t, p, serviceP, service)
	testEchoUDP(t, "127.0.0.1", svcInfo.proxyPort)
}

func TestTCPProxyUpdatePort(t *testing.T) {
	lb := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: tcpServerPort}},
		}},
	})

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	origPort := 99
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     int32(origPort),
			Protocol: "TCP",
		}}},
	}

	svcInfo := addServiceAndWaitForInfo(t, p, serviceP, service)
	testEchoTCP(t, "127.0.0.1", svcInfo.proxyPort)

	service.Spec.Ports[0].Port = 100
	p.OnServiceAdd(service)
	// Wait for the socket to actually get free.
	if err := waitForClosedPortTCP(p, origPort); err != nil {
		t.Fatalf(err.Error())
	}
	svcInfo.finished.Wait()

	svcInfo = addServiceAndWaitForInfo(t, p, serviceP, service)
	testEchoTCP(t, "127.0.0.1", svcInfo.proxyPort)
}

func TestUDPProxyUpdatePort(t *testing.T) {
	lb := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: udpServerPort}},
		}},
	})

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	origPort := 99
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     int32(origPort),
			Protocol: "UDP",
		}}},
	}

	svcInfo := addServiceAndWaitForInfo(t, p, serviceP, service)
	testEchoUDP(t, "127.0.0.1", svcInfo.proxyPort)

	service.Spec.Ports[0].Port = 100
	p.OnServiceAdd(service)
	// Wait for the socket to actually get free.
	if err := waitForClosedPortUDP(p, origPort); err != nil {
		t.Fatalf(err.Error())
	}
	svcInfo.finished.Wait()

	svcInfo = addServiceAndWaitForInfo(t, p, serviceP, service)
	testEchoUDP(t, "127.0.0.1", svcInfo.proxyPort)
}

func TestProxyUpdatePublicIPs(t *testing.T) {
	lb := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	lb.OnEndpointsAdd(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: tcpServerPort}},
		}},
	})

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	origPort := 9997
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     int32(origPort),
			Protocol: "TCP",
		}}},
	}

	svcInfo := addServiceAndWaitForInfo(t, p, serviceP, service)
	testEchoTCP(t, "127.0.0.1", svcInfo.proxyPort)

	service.Spec.ExternalIPs = []string{"4.3.2.1"}
	svcInfo = addServiceAndWaitForInfo(t, p, serviceP, service)
	// Wait for the socket to actually get free.
	if err := waitForClosedPortTCP(p, origPort); err != nil {
		t.Fatalf(err.Error())
	}
	svcInfo.finished.Wait()
	testEchoTCP(t, "127.0.0.1", svcInfo.proxyPort)
}

func TestProxyUpdatePortal(t *testing.T) {
	lb := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "echo"}, Port: "p"}
	endpoint := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "127.0.0.1"}},
			Ports:     []v1.EndpointPort{{Name: "p", Port: tcpServerPort}},
		}},
	}
	lb.OnEndpointsAdd(endpoint)

	fexec := makeFakeExec()

	p, err := createProxier(lb, net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Second, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}
	startProxier(p, t)
	defer p.shutdown()

	svcv0 := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     9997,
			Protocol: "TCP",
		}}},
	}

	svcInfo := addServiceAndWaitForInfo(t, p, service, svcv0)
	testEchoTCP(t, "127.0.0.1", svcInfo.proxyPort)

	svcv1 := &v1.Service{
		ObjectMeta: svcv0.ObjectMeta,
		Spec: v1.ServiceSpec{ClusterIP: "", Ports: []v1.ServicePort{
			svcv0.Spec.Ports[0],
		}},
	}
	p.OnServiceUpdate(svcv0, svcv1)

	// Wait for the service to be removed because it had an empty ClusterIP
	var exists bool
	for i := 0; i < 50; i++ {
		_, exists = p.getServiceInfo(service)
		if !exists {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if exists {
		t.Fatalf("service with empty ClusterIP should not be included in the proxy")
	}
	svcInfo.finished.Wait()

	svcv2 := &v1.Service{
		ObjectMeta: svcv0.ObjectMeta,
		Spec: v1.ServiceSpec{ClusterIP: "None", Ports: []v1.ServicePort{
			svcv0.Spec.Ports[0],
		}},
	}
	p.OnServiceUpdate(svcv1, svcv2)
	_, exists = p.getServiceInfo(service)
	if exists {
		t.Fatalf("service with 'None' as ClusterIP should not be included in the proxy")
	}

	svcv3 := &v1.Service{
		ObjectMeta: svcv0.ObjectMeta,
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{
			svcv0.Spec.Ports[0],
		}},
	}
	lb.OnEndpointsAdd(endpoint)
	p.OnServiceUpdate(svcv2, svcv3)
	svcInfo = waitForServiceInfo(t, p, service, svcv3, 0)
	testEchoTCP(t, "127.0.0.1", svcInfo.proxyPort)
}

type fakeRunner struct{}

// assert fakeAsyncRunner is a ProxyProvider
var _ asyncRunnerInterface = &fakeRunner{}

func (f fakeRunner) Run() {
}

func (f fakeRunner) Loop(stop <-chan struct{}) {
}

func TestOnServiceAddChangeMap(t *testing.T) {
	fexec := makeFakeExec()

	// Use long minSyncPeriod so we can test that immediate syncs work
	p, err := createProxier(NewLoadBalancerRR(), net.ParseIP("0.0.0.0"), ipttest.NewFake(), fexec, net.ParseIP("127.0.0.1"), nil, time.Minute, time.Minute, udpIdleTimeoutForTest, newProxySocket)
	if err != nil {
		t.Fatal(err)
	}

	// Fake out sync runner
	p.syncRunner = fakeRunner{}

	serviceMeta := metav1.ObjectMeta{Namespace: "testnamespace", Name: "testname"}
	service := &v1.Service{
		ObjectMeta: serviceMeta,
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.4", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     99,
			Protocol: "TCP",
		}}},
	}

	serviceUpdate := &v1.Service{
		ObjectMeta: serviceMeta,
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.5", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     100,
			Protocol: "TCP",
		}}},
	}

	serviceUpdate2 := &v1.Service{
		ObjectMeta: serviceMeta,
		Spec: v1.ServiceSpec{ClusterIP: "1.2.3.6", Ports: []v1.ServicePort{{
			Name:     "p",
			Port:     101,
			Protocol: "TCP",
		}}},
	}

	type onServiceTest struct {
		detail         string
		changes        []serviceChange
		expectedChange *serviceChange
	}

	tests := []onServiceTest{
		{
			detail: "add",
			changes: []serviceChange{
				{current: service},
			},
			expectedChange: &serviceChange{
				current: service,
			},
		},
		{
			detail: "add+update=add",
			changes: []serviceChange{
				{current: service},
				{
					previous: service,
					current:  serviceUpdate,
				},
			},
			expectedChange: &serviceChange{
				current: serviceUpdate,
			},
		},
		{
			detail: "add+del=none",
			changes: []serviceChange{
				{current: service},
				{previous: service},
			},
		},
		{
			detail: "update+update=update",
			changes: []serviceChange{
				{
					previous: service,
					current:  serviceUpdate,
				},
				{
					previous: serviceUpdate,
					current:  serviceUpdate2,
				},
			},
			expectedChange: &serviceChange{
				previous: service,
				current:  serviceUpdate2,
			},
		},
		{
			detail: "update+del=del",
			changes: []serviceChange{
				{
					previous: service,
					current:  serviceUpdate,
				},
				{previous: serviceUpdate},
			},
			// change collapsing always keeps the oldest service
			// info since correct unmerging depends on the least
			// recent update, not the most current.
			expectedChange: &serviceChange{
				previous: service,
			},
		},
		{
			detail: "del+add=update",
			changes: []serviceChange{
				{previous: service},
				{current: serviceUpdate},
			},
			expectedChange: &serviceChange{
				previous: service,
				current:  serviceUpdate,
			},
		},
	}

	for _, test := range tests {
		for _, change := range test.changes {
			p.serviceChange(change.previous, change.current, test.detail)
		}

		if test.expectedChange != nil {
			if len(p.serviceChanges) != 1 {
				t.Fatalf("[%s] expected 1 service change but found %d", test.detail, len(p.serviceChanges))
			}
			expectedService := test.expectedChange.current
			if expectedService == nil {
				expectedService = test.expectedChange.previous
			}
			svcName := types.NamespacedName{Namespace: expectedService.Namespace, Name: expectedService.Name}

			change, ok := p.serviceChanges[svcName]
			if !ok {
				t.Fatalf("[%s] did not find service change for %v", test.detail, svcName)
			}
			if !reflect.DeepEqual(change.previous, test.expectedChange.previous) {
				t.Fatalf("[%s] change previous service and expected previous service don't match\nchange: %+v\nexp:    %+v", test.detail, change.previous, test.expectedChange.previous)
			}
			if !reflect.DeepEqual(change.current, test.expectedChange.current) {
				t.Fatalf("[%s] change current service and expected current service don't match\nchange: %+v\nexp:    %+v", test.detail, change.current, test.expectedChange.current)
			}
		} else {
			if len(p.serviceChanges) != 0 {
				t.Fatalf("[%s] expected no service changes but found %d", test.detail, len(p.serviceChanges))
			}
		}
	}
}

func TestNoopEndpointSlice(t *testing.T) {
	p := Proxier{}
	p.OnEndpointSliceAdd(&discovery.EndpointSlice{})
	p.OnEndpointSliceUpdate(&discovery.EndpointSlice{}, &discovery.EndpointSlice{})
	p.OnEndpointSliceDelete(&discovery.EndpointSlice{})
	p.OnEndpointSlicesSynced()
}

func makeFakeExec() *fakeexec.FakeExec {
	fcmd := fakeexec.FakeCmd{
		CombinedOutputScript: []fakeexec.FakeAction{
			func() ([]byte, []byte, error) { return []byte("1 flow entries have been deleted"), nil, nil },
		},
	}
	return &fakeexec.FakeExec{
		CommandScript: []fakeexec.FakeCommandAction{
			func(cmd string, args ...string) exec.Cmd { return fakeexec.InitFakeCmd(&fcmd, cmd, args...) },
		},
		LookPathFunc: func(cmd string) (string, error) { return cmd, nil },
	}
}

// TODO(justinsb): Add test for nodePort conflict detection, once we have nodePort wired in
