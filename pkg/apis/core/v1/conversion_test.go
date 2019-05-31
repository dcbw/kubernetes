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

package v1_test

import (
	"encoding/json"
	"math/rand"
	"net/url"
	"reflect"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metafuzzer "k8s.io/apimachinery/pkg/apis/meta/fuzzer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	apps "k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/core"
	corefuzzer "k8s.io/kubernetes/pkg/apis/core/fuzzer"
	corev1 "k8s.io/kubernetes/pkg/apis/core/v1"
	utilpointer "k8s.io/utils/pointer"

	// enforce that all types are installed
	_ "k8s.io/kubernetes/pkg/api/testapi"
)

func TestPodLogOptions(t *testing.T) {
	sinceSeconds := int64(1)
	sinceTime := metav1.NewTime(time.Date(2000, 1, 1, 12, 34, 56, 0, time.UTC).Local())
	tailLines := int64(2)
	limitBytes := int64(3)

	versionedLogOptions := &v1.PodLogOptions{
		Container:    "mycontainer",
		Follow:       true,
		Previous:     true,
		SinceSeconds: &sinceSeconds,
		SinceTime:    &sinceTime,
		Timestamps:   true,
		TailLines:    &tailLines,
		LimitBytes:   &limitBytes,
	}
	unversionedLogOptions := &core.PodLogOptions{
		Container:    "mycontainer",
		Follow:       true,
		Previous:     true,
		SinceSeconds: &sinceSeconds,
		SinceTime:    &sinceTime,
		Timestamps:   true,
		TailLines:    &tailLines,
		LimitBytes:   &limitBytes,
	}
	expectedParameters := url.Values{
		"container":    {"mycontainer"},
		"follow":       {"true"},
		"previous":     {"true"},
		"sinceSeconds": {"1"},
		"sinceTime":    {"2000-01-01T12:34:56Z"},
		"timestamps":   {"true"},
		"tailLines":    {"2"},
		"limitBytes":   {"3"},
	}

	codec := runtime.NewParameterCodec(legacyscheme.Scheme)

	// unversioned -> query params
	{
		actualParameters, err := codec.EncodeParameters(unversionedLogOptions, v1.SchemeGroupVersion)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actualParameters, expectedParameters) {
			t.Fatalf("Expected\n%#v\ngot\n%#v", expectedParameters, actualParameters)
		}
	}

	// versioned -> query params
	{
		actualParameters, err := codec.EncodeParameters(versionedLogOptions, v1.SchemeGroupVersion)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actualParameters, expectedParameters) {
			t.Fatalf("Expected\n%#v\ngot\n%#v", expectedParameters, actualParameters)
		}
	}

	// query params -> versioned
	{
		convertedLogOptions := &v1.PodLogOptions{}
		err := codec.DecodeParameters(expectedParameters, v1.SchemeGroupVersion, convertedLogOptions)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(convertedLogOptions, versionedLogOptions) {
			t.Fatalf("Unexpected deserialization:\n%s", diff.ObjectGoPrintSideBySide(versionedLogOptions, convertedLogOptions))
		}
	}

	// query params -> unversioned
	{
		convertedLogOptions := &core.PodLogOptions{}
		err := codec.DecodeParameters(expectedParameters, v1.SchemeGroupVersion, convertedLogOptions)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(convertedLogOptions, unversionedLogOptions) {
			t.Fatalf("Unexpected deserialization:\n%s", diff.ObjectGoPrintSideBySide(unversionedLogOptions, convertedLogOptions))
		}
	}
}

// TestPodSpecConversion tests that v1.ServiceAccount is an alias for
// ServiceAccountName.
func TestPodSpecConversion(t *testing.T) {
	name, other := "foo", "bar"

	// Test internal -> v1. Should have both alias (DeprecatedServiceAccount)
	// and new field (ServiceAccountName).
	i := &core.PodSpec{
		ServiceAccountName: name,
	}
	v := v1.PodSpec{}
	if err := legacyscheme.Scheme.Convert(i, &v, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.ServiceAccountName != name {
		t.Fatalf("want v1.ServiceAccountName %q, got %q", name, v.ServiceAccountName)
	}
	if v.DeprecatedServiceAccount != name {
		t.Fatalf("want v1.DeprecatedServiceAccount %q, got %q", name, v.DeprecatedServiceAccount)
	}

	// Test v1 -> internal. Either DeprecatedServiceAccount, ServiceAccountName,
	// or both should translate to ServiceAccountName. ServiceAccountName wins
	// if both are set.
	testCases := []*v1.PodSpec{
		// New
		{ServiceAccountName: name},
		// Alias
		{DeprecatedServiceAccount: name},
		// Both: same
		{ServiceAccountName: name, DeprecatedServiceAccount: name},
		// Both: different
		{ServiceAccountName: name, DeprecatedServiceAccount: other},
	}
	for k, v := range testCases {
		got := core.PodSpec{}
		err := legacyscheme.Scheme.Convert(v, &got, nil)
		if err != nil {
			t.Fatalf("unexpected error for case %d: %v", k, err)
		}
		if got.ServiceAccountName != name {
			t.Fatalf("want core.ServiceAccountName %q, got %q", name, got.ServiceAccountName)
		}
	}
}

func TestResourceListConversion(t *testing.T) {
	bigMilliQuantity := resource.NewQuantity(resource.MaxMilliValue, resource.DecimalSI)
	bigMilliQuantity.Add(resource.MustParse("12345m"))

	tests := []struct {
		input    v1.ResourceList
		expected core.ResourceList
	}{
		{ // No changes necessary.
			input: v1.ResourceList{
				v1.ResourceMemory:  resource.MustParse("30M"),
				v1.ResourceCPU:     resource.MustParse("100m"),
				v1.ResourceStorage: resource.MustParse("1G"),
			},
			expected: core.ResourceList{
				core.ResourceMemory:  resource.MustParse("30M"),
				core.ResourceCPU:     resource.MustParse("100m"),
				core.ResourceStorage: resource.MustParse("1G"),
			},
		},
		{ // Nano-scale values should be rounded up to milli-scale.
			input: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("3.000023m"),
				v1.ResourceMemory: resource.MustParse("500.000050m"),
			},
			expected: core.ResourceList{
				core.ResourceCPU:    resource.MustParse("4m"),
				core.ResourceMemory: resource.MustParse("501m"),
			},
		},
		{ // Large values should still be accurate.
			input: v1.ResourceList{
				v1.ResourceCPU:     *bigMilliQuantity.Copy(),
				v1.ResourceStorage: *bigMilliQuantity.Copy(),
			},
			expected: core.ResourceList{
				core.ResourceCPU:     *bigMilliQuantity.Copy(),
				core.ResourceStorage: *bigMilliQuantity.Copy(),
			},
		},
	}

	for i, test := range tests {
		output := core.ResourceList{}

		// defaulting is a separate step from conversion that is applied when reading from the API or from etcd.
		// perform that step explicitly.
		corev1.SetDefaults_ResourceList(&test.input)

		err := legacyscheme.Scheme.Convert(&test.input, &output, nil)
		if err != nil {
			t.Fatalf("unexpected error for case %d: %v", i, err)
		}
		if !apiequality.Semantic.DeepEqual(test.expected, output) {
			t.Errorf("unexpected conversion for case %d: Expected\n%+v;\nGot\n%+v", i, test.expected, output)
		}
	}
}

func TestReplicationControllerConversion(t *testing.T) {
	// If we start with a RC, we should always have round-trip fidelity.
	inputs := []*v1.ReplicationController{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "name",
				Namespace: "namespace",
			},
			Spec: v1.ReplicationControllerSpec{
				Replicas:        utilpointer.Int32Ptr(1),
				MinReadySeconds: 32,
				Selector:        map[string]string{"foo": "bar", "bar": "foo"},
				Template: &v1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"foo": "bar", "bar": "foo"},
					},
					Spec: v1.PodSpec{
						Containers: []v1.Container{
							{
								Name:  "container",
								Image: "image",
							},
						},
					},
				},
			},
			Status: v1.ReplicationControllerStatus{
				Replicas:             1,
				FullyLabeledReplicas: 2,
				ReadyReplicas:        3,
				AvailableReplicas:    4,
				ObservedGeneration:   5,
				Conditions: []v1.ReplicationControllerCondition{
					{
						Type:               v1.ReplicationControllerReplicaFailure,
						Status:             v1.ConditionTrue,
						LastTransitionTime: metav1.NewTime(time.Unix(123456789, 0)),
						Reason:             "Reason",
						Message:            "Message",
					},
				},
			},
		},
	}

	// Add some fuzzed RCs.
	apiObjectFuzzer := fuzzer.FuzzerFor(fuzzer.MergeFuzzerFuncs(metafuzzer.Funcs, corefuzzer.Funcs), rand.NewSource(152), legacyscheme.Codecs)
	for i := 0; i < 100; i++ {
		rc := &v1.ReplicationController{}
		apiObjectFuzzer.Fuzz(rc)
		// Sometimes the fuzzer decides to leave Spec.Template nil.
		// We can't support that because Spec.Template is not a pointer in RS,
		// so it will round-trip as non-nil but empty.
		if rc.Spec.Template == nil {
			rc.Spec.Template = &v1.PodTemplateSpec{}
		}
		// Sometimes the fuzzer decides to insert an empty label key.
		// This doesn't round-trip properly because it's invalid.
		if rc.Spec.Selector != nil {
			delete(rc.Spec.Selector, "")
		}
		inputs = append(inputs, rc)
	}

	// Round-trip the input RCs before converting to RS.
	for i := range inputs {
		inputs[i] = roundTrip(t, inputs[i]).(*v1.ReplicationController)
	}

	for _, in := range inputs {
		rs := &apps.ReplicaSet{}
		// Use in.DeepCopy() to avoid sharing pointers with `in`.
		if err := corev1.Convert_v1_ReplicationController_To_apps_ReplicaSet(in.DeepCopy(), rs, nil); err != nil {
			t.Errorf("can't convert RC to RS: %v", err)
			continue
		}
		// Round-trip RS before converting back to RC.
		rs = roundTripRS(t, rs)
		out := &v1.ReplicationController{}
		if err := corev1.Convert_apps_ReplicaSet_To_v1_ReplicationController(rs, out, nil); err != nil {
			t.Errorf("can't convert RS to RC: %v", err)
			continue
		}
		if !apiequality.Semantic.DeepEqual(in, out) {
			instr, _ := json.MarshalIndent(in, "", "  ")
			outstr, _ := json.MarshalIndent(out, "", "  ")
			t.Errorf("RC-RS conversion round-trip failed:\nin:\n%s\nout:\n%s", instr, outstr)
		}
	}
}

func roundTripRS(t *testing.T, rs *apps.ReplicaSet) *apps.ReplicaSet {
	codec := legacyscheme.Codecs.LegacyCodec(appsv1.SchemeGroupVersion)
	data, err := runtime.Encode(codec, rs)
	if err != nil {
		t.Errorf("%v\n %#v", err, rs)
		return nil
	}
	obj2, err := runtime.Decode(codec, data)
	if err != nil {
		t.Errorf("%v\nData: %s\nSource: %#v", err, string(data), rs)
		return nil
	}
	obj3 := &apps.ReplicaSet{}
	err = legacyscheme.Scheme.Convert(obj2, obj3, nil)
	if err != nil {
		t.Errorf("%v\nSource: %#v", err, obj2)
		return nil
	}
	return obj3
}

func Test_core_PodStatus_to_v1_PodStatus(t *testing.T) {
	// core to v1
	testInputs := []core.PodStatus{
		{
			// we have list but no IP
			PodIPs: []core.PodIP{
				{
					IP:         "1.1.1.1",
					Properties: make(map[string]string),
				},
				{
					IP:         "2.2.2.2",
					Properties: make(map[string]string),
				},
			},
		},
	}
	for _, input := range testInputs {
		v1PodStatus := v1.PodStatus{}
		if err := corev1.Convert_core_PodStatus_To_v1_PodStatus(&input, &v1PodStatus, nil); nil != err {
			t.Errorf("Convert core.PodStatus to v1.PodStatus failed with error %v", err.Error())
		}

		// Primary IP was not set..
		if len(v1PodStatus.PodIP) == 0 {
			t.Errorf("Convert core.PodStatus to v1.PodStatus failed out.PodIP is empty, should be %v", v1PodStatus.PodIP)
		}

		// Primary should always == in.PodIPs[0].IP
		if len(input.PodIPs) > 0 && v1PodStatus.PodIP != input.PodIPs[0].IP {
			t.Errorf("Convert core.PodStatus to v1.PodStatus failed out.PodIP != in.PodIP[0].IP expected %v found %v", input.PodIPs[0].IP, v1PodStatus.PodIP)
		}
		// match v1.PodIPs to core.PodIPs
		for idx := range input.PodIPs {
			if v1PodStatus.PodIPs[idx].IP != input.PodIPs[idx].IP {
				t.Errorf("Convert core.PodStatus to v1.PodStatus failed. Expected v1.PodStatus[%v]=%v but found %v", idx, input.PodIPs[idx].IP, v1PodStatus.PodIPs[idx].IP)
			}
		}
	}
}
func Test_v1_PodStatus_to_core_PodStatus(t *testing.T) {
	// fail
	v1FailTestInputs := []v1.PodStatus{
		{
			PodIP: "1.1.2.1", // fail becaue PodIP != PodIPs[0]
			PodIPs: []v1.PodIP{
				{IP: "1.1.1.1"},
				{IP: "2.2.2.2"},
			},
		},
	}
	// success
	v1TestInputs := []v1.PodStatus{
		// only list of IPs
		{
			PodIPs: []v1.PodIP{
				{IP: "1.1.1.1"},
				{IP: "2.2.2.2"},
			},
		},
		// only Primary IP Provided
		{
			PodIP: "1.1.1.1",
		},
		// Both
		{
			PodIP: "1.1.1.1",
			PodIPs: []v1.PodIP{
				{IP: "1.1.1.1"},
				{IP: "2.2.2.2"},
			},
		},
		// v4 and v6
		{
			PodIP: "1.1.1.1",
			PodIPs: []v1.PodIP{
				{IP: "1.1.1.1"},
				{IP: "ace:cab:deca::/8"},
			},
		},
	}
	// run failed cases
	for _, failedTest := range v1FailTestInputs {
		corePodStatus := core.PodStatus{}
		// convert..
		if err := corev1.Convert_v1_PodStatus_To_core_PodStatus(&failedTest, &corePodStatus, nil); err == nil {
			t.Errorf("Convert v1.PodStatus to core.PodStatus should have failed for input %+v", failedTest)
		}
	}

	// run ok cases
	for _, testInput := range v1TestInputs {
		corePodStatus := core.PodStatus{}
		// convert..
		if err := corev1.Convert_v1_PodStatus_To_core_PodStatus(&testInput, &corePodStatus, nil); err != nil {
			t.Errorf("Convert v1.PodStatus to core.PodStatus failed with error:%v for input %+v", err.Error(), testInput)
		}

		// List should have at least 1 IP == v1.PodIP || v1.PodIPs[0] (whichever provided)
		if len(testInput.PodIP) > 0 && corePodStatus.PodIPs[0].IP != testInput.PodIP {
			t.Errorf("Convert v1.PodStatus to core.PodStatus failed. expected corePodStatus.PodIPs[0].ip=%v found %v", corePodStatus.PodIPs[0].IP, corePodStatus.PodIPs[0].IP)
		}

		// walk the list
		for idx := range testInput.PodIPs {
			if corePodStatus.PodIPs[idx].IP != testInput.PodIPs[idx].IP {
				t.Errorf("Convert v1.PodStatus to core.PodStatus failed core.PodIPs[%v]=%v expected %v", idx, corePodStatus.PodIPs[idx].IP, testInput.PodIPs[idx].IP)
			}
		}

		// if input has a list of IPs
		// then out put should have the same length
		if len(testInput.PodIPs) > 0 && len(testInput.PodIPs) != len(corePodStatus.PodIPs) {
			t.Errorf("Convert v1.PodStatus to core.PodStatus failed len(core.PodIPs) != len(v1.PodStatus.PodIPs) [%v]=[%v]", len(corePodStatus.PodIPs), len(testInput.PodIPs))
		}
	}
}

func Test_core_NodeSpec_to_v1_NodeSpec(t *testing.T) {
	// core to v1
	testInputs := []core.NodeSpec{
		{
			PodCIDRs: []string{"10.0.0.0/24", "10.0.1.0/24"},
		},
		{
			PodCIDRs: []string{"10.0.0.0/24", "ace:cab:deca::/8"},
		},
	}

	for _, testInput := range testInputs {
		v1NodeSpec := v1.NodeSpec{}
		// convert
		if err := corev1.Convert_core_NodeSpec_To_v1_NodeSpec(&testInput, &v1NodeSpec, nil); nil != err {
			t.Errorf("Convert core.NodeSpec to v1.NodeSpec failed with error %v", err.Error())
		}

		// validate results
		if v1NodeSpec.PodCIDR != testInput.PodCIDRs[0] {
			t.Errorf("Convert core.NodeSpec to v1.NodeSpec failed. Expected v1.PodCIDR=%v but found %v", testInput.PodCIDRs[0], v1NodeSpec.PodCIDR)
		}

		// match v1.PodIPs to core.PodIPs
		for idx := range testInput.PodCIDRs {
			if v1NodeSpec.PodCIDRs[idx] != testInput.PodCIDRs[idx] {
				t.Errorf("Convert core.NodeSpec to v1.NodeSpec failed. Expected v1.NodeSpec[%v]=%v but found %v", idx, testInput.PodCIDRs[idx], v1NodeSpec.PodCIDRs[idx])
			}
		}
	}
}

func Test_v1_NodeSpec_to_core_NodeSpec(t *testing.T) {

	failInputs := []v1.NodeSpec{
		{
			PodCIDR:  "10.0.0.0/24",
			PodCIDRs: []string{"10.0.1.0/24", "ace:cab:deca::/8"},
		},
	}

	testInputs := []v1.NodeSpec{
		// Both are provided
		{
			PodCIDR:  "10.0.1.0/24",
			PodCIDRs: []string{"10.0.1.0/24", "ace:cab:deca::/8"},
		},
		// list only
		{
			PodCIDRs: []string{"10.0.1.0/24", "ace:cab:deca::/8"},
		},
		// cidr only
		{
			PodCIDR: "10.0.1.0/24",
		},
	}

	// fail cases
	for _, failInput := range failInputs {
		coreNodeSpec := core.NodeSpec{}
		if err := corev1.Convert_v1_NodeSpec_To_core_NodeSpec(&failInput, &coreNodeSpec, nil); err == nil {
			t.Errorf("Convert v1.NodeSpec to core.NodeSpec failed. Expected an error when coreNodeSpec.PodCIDR != coreNodeSpec.PodCIDRs[0]")
		}
	}

	for _, testInput := range testInputs {
		coreNodeSpec := core.NodeSpec{}
		if err := corev1.Convert_v1_NodeSpec_To_core_NodeSpec(&testInput, &coreNodeSpec, nil); err != nil {
			t.Errorf("Convert v1.NodeSpec to core.NodeSpec failed with error:%v", err.Error())
		}
		if len(testInput.PodCIDR) > 0 && coreNodeSpec.PodCIDRs[0] != testInput.PodCIDR {
			t.Errorf("Convert v1.NodeSpec to core.NodeSpec failed. expected coreNodeSpec.PodCIDRs[0]=%v found %v", testInput.PodCIDR, coreNodeSpec.PodCIDRs[0])
		}
		// match ip list
		for idx := range testInput.PodCIDRs {
			if coreNodeSpec.PodCIDRs[idx] != testInput.PodCIDRs[idx] {
				t.Errorf("Convert v1.NodeSpec to core.NodeSpec failed core.PodCIDRs[%v]=%v expected %v", idx, coreNodeSpec.PodCIDRs[idx], testInput.PodCIDRs[idx])
			}
		}
	}
}
