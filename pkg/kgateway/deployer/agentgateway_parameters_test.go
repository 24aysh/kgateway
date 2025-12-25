package deployer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/agentgateway"
	"github.com/kgateway-dev/kgateway/v2/pkg/deployer"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/collections"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/ir"
)

func TestAgentgatewayParametersApplier_ApplyToHelmValues_Image(t *testing.T) {
	params := &agentgateway.AgentgatewayParameters{
		Spec: agentgateway.AgentgatewayParametersSpec{
			AgentgatewayParametersConfigs: agentgateway.AgentgatewayParametersConfigs{
				Image: &agentgateway.Image{
					Registry:   ptr.To("custom.registry.io"),
					Repository: ptr.To("custom/agentgateway"),
					Tag:        ptr.To("v1.0.0"),
				},
			},
		},
	}

	applier := NewAgentgatewayParametersApplier(params)
	vals := &deployer.HelmConfig{
		Agentgateway: &deployer.AgentgatewayHelmGateway{},
	}

	applier.ApplyToHelmValues(vals)

	require.NotNil(t, vals.Agentgateway.Image)
	assert.Equal(t, "custom.registry.io", *vals.Agentgateway.Image.Registry)
	assert.Equal(t, "custom/agentgateway", *vals.Agentgateway.Image.Repository)
	assert.Equal(t, "v1.0.0", *vals.Agentgateway.Image.Tag)
}

func TestAgentgatewayParametersApplier_ApplyToHelmValues_Resources(t *testing.T) {
	params := &agentgateway.AgentgatewayParameters{
		Spec: agentgateway.AgentgatewayParametersSpec{
			AgentgatewayParametersConfigs: agentgateway.AgentgatewayParametersConfigs{
				Resources: &corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("512Mi"),
						corev1.ResourceCPU:    resource.MustParse("500m"),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("256Mi"),
						corev1.ResourceCPU:    resource.MustParse("250m"),
					},
				},
			},
		},
	}

	applier := NewAgentgatewayParametersApplier(params)
	vals := &deployer.HelmConfig{
		Agentgateway: &deployer.AgentgatewayHelmGateway{},
	}

	applier.ApplyToHelmValues(vals)

	require.NotNil(t, vals.Agentgateway.Resources)
	assert.Equal(t, "512Mi", vals.Agentgateway.Resources.Limits.Memory().String())
	assert.Equal(t, "500m", vals.Agentgateway.Resources.Limits.Cpu().String())
}

func TestAgentgatewayParametersApplier_ApplyToHelmValues_Env(t *testing.T) {
	params := &agentgateway.AgentgatewayParameters{
		Spec: agentgateway.AgentgatewayParametersSpec{
			AgentgatewayParametersConfigs: agentgateway.AgentgatewayParametersConfigs{
				Env: []corev1.EnvVar{
					{Name: "CUSTOM_VAR", Value: "custom_value"},
					{Name: "ANOTHER_VAR", Value: "another_value"},
				},
			},
		},
	}

	applier := NewAgentgatewayParametersApplier(params)
	vals := &deployer.HelmConfig{
		Agentgateway: &deployer.AgentgatewayHelmGateway{},
	}

	applier.ApplyToHelmValues(vals)

	require.Len(t, vals.Agentgateway.Env, 2)
	assert.Equal(t, "CUSTOM_VAR", vals.Agentgateway.Env[0].Name)
	assert.Equal(t, "ANOTHER_VAR", vals.Agentgateway.Env[1].Name)
}

func TestAgentgatewayParametersApplier_ApplyOverlaysToObjects(t *testing.T) {
	specPatch := []byte(`{
		"replicas": 3
	}`)

	params := &agentgateway.AgentgatewayParameters{
		Spec: agentgateway.AgentgatewayParametersSpec{
			AgentgatewayParametersOverlays: agentgateway.AgentgatewayParametersOverlays{
				Deployment: &agentgateway.KubernetesResourceOverlay{
					Metadata: &agentgateway.AgentgatewayParametersObjectMetadata{
						Labels: map[string]string{
							"overlay-label": "overlay-value",
						},
					},
					Spec: &apiextensionsv1.JSON{Raw: specPatch},
				},
			},
		},
	}

	applier := NewAgentgatewayParametersApplier(params)

	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-deployment",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
		},
	}
	objs := []client.Object{deployment}

	err := applier.ApplyOverlaysToObjects(objs)
	require.NoError(t, err)

	result := objs[0].(*appsv1.Deployment)
	assert.Equal(t, int32(3), *result.Spec.Replicas)
	assert.Equal(t, "overlay-value", result.Labels["overlay-label"])
}

func TestAgentgatewayParametersApplier_ApplyOverlaysToObjects_NilParams(t *testing.T) {
	applier := NewAgentgatewayParametersApplier(nil)

	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-deployment",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
		},
	}
	objs := []client.Object{deployment}

	err := applier.ApplyOverlaysToObjects(objs)
	require.NoError(t, err)

	result := objs[0].(*appsv1.Deployment)
	assert.Equal(t, int32(1), *result.Spec.Replicas)
}

func TestAgentgatewayParametersApplier_ApplyToHelmValues_RawConfig(t *testing.T) {
	rawConfigJSON := []byte(`{
		"tracing": {
			"otlpEndpoint": "http://jaeger:4317"
		},
		"metrics": {
			"enabled": true
		}
	}`)

	params := &agentgateway.AgentgatewayParameters{
		Spec: agentgateway.AgentgatewayParametersSpec{
			AgentgatewayParametersConfigs: agentgateway.AgentgatewayParametersConfigs{
				RawConfig: &apiextensionsv1.JSON{Raw: rawConfigJSON},
			},
		},
	}

	applier := NewAgentgatewayParametersApplier(params)
	vals := &deployer.HelmConfig{
		Agentgateway: &deployer.AgentgatewayHelmGateway{},
	}

	applier.ApplyToHelmValues(vals)
	assert.Equal(t, vals.Agentgateway.RawConfig.Raw, rawConfigJSON)
}

func TestAgentgatewayParametersApplier_ApplyToHelmValues_RawConfigWithLogging(t *testing.T) {
	// rawConfig has logging.format, but typed Logging.Format should take precedence
	// (merging happens in helm template, but here we test both are passed through)
	rawConfigJSON := []byte(`{
		"logging": {
			"format": "json"
		},
		"tracing": {
			"otlpEndpoint": "http://jaeger:4317"
		}
	}`)

	params := &agentgateway.AgentgatewayParameters{
		Spec: agentgateway.AgentgatewayParametersSpec{
			AgentgatewayParametersConfigs: agentgateway.AgentgatewayParametersConfigs{
				Logging: &agentgateway.AgentgatewayParametersLogging{
					Format: agentgateway.AgentgatewayParametersLoggingText,
				},
				RawConfig: &apiextensionsv1.JSON{Raw: rawConfigJSON},
			},
		},
	}

	applier := NewAgentgatewayParametersApplier(params)
	vals := &deployer.HelmConfig{
		Agentgateway: &deployer.AgentgatewayHelmGateway{},
	}

	applier.ApplyToHelmValues(vals)

	// Both should be set - merging happens in helm template
	assert.Equal(t, "text", string(vals.Agentgateway.Logging.Format))
	assert.Equal(t, vals.Agentgateway.RawConfig.Raw, rawConfigJSON)
}

func TestGetDefaultAgentgatewayHelmValues_LoadBalancerIP(t *testing.T) {
	originalGetGatewayIR := deployer.GetGatewayIR
	t.Cleanup(func() {
		deployer.GetGatewayIR = originalGetGatewayIR
	})

	tests := []struct {
		name        string
		addresses   []gwv1.GatewaySpecAddress
		wantIP      *string
		wantErr     bool
		errContains string
	}{
		{
			name: "single valid IPv4 address sets loadBalancerIP",
			addresses: []gwv1.GatewaySpecAddress{
				{Type: ptr.To(gwv1.IPAddressType), Value: "203.0.113.10"},
			},
			wantIP:  ptr.To("203.0.113.10"),
			wantErr: false,
		},
		{
			name: "single valid IPv6 address sets loadBalancerIP",
			addresses: []gwv1.GatewaySpecAddress{
				{Type: ptr.To(gwv1.IPAddressType), Value: "2001:db8::1"},
			},
			wantIP:  ptr.To("2001:db8::1"),
			wantErr: false,
		},
		{
			name: "nil address type defaults to IPAddressType",
			addresses: []gwv1.GatewaySpecAddress{
				{Type: nil, Value: "192.0.2.1"},
			},
			wantIP:  ptr.To("192.0.2.1"),
			wantErr: false,
		},
		{
			name:      "empty addresses array does not set IP",
			addresses: []gwv1.GatewaySpecAddress{},
			wantIP:    nil,
			wantErr:   false,
		},
		{
			name: "multiple IP addresses returns error",
			addresses: []gwv1.GatewaySpecAddress{
				{Type: ptr.To(gwv1.IPAddressType), Value: "203.0.113.10"},
				{Type: ptr.To(gwv1.IPAddressType), Value: "203.0.113.11"},
			},
			wantIP:      nil,
			wantErr:     true,
			errContains: "multiple addresses",
		},
		{
			name: "hostname address returns error",
			addresses: []gwv1.GatewaySpecAddress{
				{Type: ptr.To(gwv1.HostnameAddressType), Value: "example.com"},
			},
			wantIP:      nil,
			wantErr:     true,
			errContains: "no valid IP address",
		},
		{
			name: "invalid IP address returns error",
			addresses: []gwv1.GatewaySpecAddress{
				{Type: ptr.To(gwv1.IPAddressType), Value: "not-an-ip"},
			},
			wantIP:      nil,
			wantErr:     true,
			errContains: "no valid IP address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := &gwv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: gwv1.GatewaySpec{
					GatewayClassName: "agentgateway",
					Addresses:        tt.addresses,
					Listeners: []gwv1.Listener{
						{
							Name:     "http",
							Port:     8080,
							Protocol: gwv1.HTTPProtocolType,
						},
					},
				},
			}

			deployer.GetGatewayIR = func(gw *gwv1.Gateway, _ *collections.CommonCollections) *ir.GatewayForDeployer {
				return deployer.GatewayIRFrom(gw, "kgateway.dev/agentgateway")
			}

			gen := &agentgatewayParametersHelmValuesGenerator{
				inputs: &deployer.Inputs{
					ControlPlane: deployer.ControlPlaneInfo{
						XdsHost:    "xds.example.com",
						AgwXdsPort: 9977,
						XdsTLS:     false,
					},
					CommonCollections: nil,
				},
			}

			vals, err := gen.getDefaultAgentgatewayHelmValues(gw)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, vals)
			require.NotNil(t, vals.Agentgateway)
			require.NotNil(t, vals.Agentgateway.Service)
			assert.Equal(t, string(corev1.ServiceTypeLoadBalancer), *vals.Agentgateway.Service.Type)

			if tt.wantIP == nil {
				assert.Nil(t, vals.Agentgateway.Service.LoadBalancerIP)
			} else {
				require.NotNil(t, vals.Agentgateway.Service.LoadBalancerIP)
				assert.Equal(t, *tt.wantIP, *vals.Agentgateway.Service.LoadBalancerIP)
			}
		})
	}
}
