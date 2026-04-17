package listenerpolicy

import (
	"testing"

	envoyrbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	envoyrbacnetwork "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/rbac/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sharedv1alpha1 "github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/ir"
)

func TestTranslateNetworkRbac_Nil(t *testing.T) {
	result, err := translateNetworkRbac(nil, ir.ObjectSource{})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestTranslateNetworkRbac_EmptyMatchExpressions(t *testing.T) {
	rbac := &sharedv1alpha1.Authorization{
		Policy: sharedv1alpha1.AuthorizationPolicy{
			MatchExpressions: []sharedv1alpha1.CELExpression{},
		},
		Action: sharedv1alpha1.AuthorizationPolicyActionAllow,
	}

	objSrc := ir.ObjectSource{
		Namespace: "test-ns",
		Name:      "test-policy",
	}

	result, err := translateNetworkRbac(rbac, objSrc)
	require.NoError(t, err)
	require.NotNil(t, result)

	var rbacConfig envoyrbacnetwork.RBAC
	err = result.UnmarshalTo(&rbacConfig)
	require.NoError(t, err)

	// Empty expressions → deny-all via DENY action with no policies.
	assert.Equal(t, "test-ns_test-policy_network_rbac", rbacConfig.StatPrefix)
	assert.NotNil(t, rbacConfig.Rules)
	assert.Equal(t, envoyrbacv3.RBAC_DENY, rbacConfig.Rules.Action)
	assert.Empty(t, rbacConfig.Rules.Policies)

	// Must NOT use the matcher field — that would require HttpAttributesCelMatchInput
	// which is rejected by Envoy at the network (L4) layer.
	assert.Nil(t, rbacConfig.Matcher, "network RBAC must not use the matcher field (requires HTTP-level inputs)")
}

// TestTranslateNetworkRbac_ExactIP_Allow verifies that an exact-IP CEL expression
// produces a valid connection-level RBAC rule using Principal.SourceIp.
func TestTranslateNetworkRbac_ExactIP_Allow(t *testing.T) {
	rbac := &sharedv1alpha1.Authorization{
		Policy: sharedv1alpha1.AuthorizationPolicy{
			MatchExpressions: []sharedv1alpha1.CELExpression{
				`source.address == "10.0.0.1"`,
			},
		},
		Action: sharedv1alpha1.AuthorizationPolicyActionAllow,
	}

	objSrc := ir.ObjectSource{Namespace: "test-ns", Name: "test-policy"}

	result, err := translateNetworkRbac(rbac, objSrc)
	require.NoError(t, err)
	require.NotNil(t, result)

	var rbacConfig envoyrbacnetwork.RBAC
	require.NoError(t, result.UnmarshalTo(&rbacConfig))

	assert.Equal(t, "test-ns_test-policy_network_rbac", rbacConfig.StatPrefix)
	assert.Nil(t, rbacConfig.Matcher, "network RBAC must not use the matcher field")

	require.NotNil(t, rbacConfig.Rules)
	assert.Equal(t, envoyrbacv3.RBAC_ALLOW, rbacConfig.Rules.Action)

	policy, ok := rbacConfig.Rules.Policies["network-ip-policy"]
	require.True(t, ok, "expected policy 'network-ip-policy'")
	require.Len(t, policy.Principals, 1)

	sourceIP := policy.Principals[0].GetSourceIp()
	require.NotNil(t, sourceIP, "expected Principal.SourceIp for single CIDR")
	assert.Equal(t, "10.0.0.1", sourceIP.AddressPrefix)
	assert.Equal(t, uint32(32), sourceIP.PrefixLen.Value)
}

// TestTranslateNetworkRbac_PrefixStartsWith_Allow verifies that a startsWith CEL
// expression is correctly mapped to a CIDR-range Principal.
func TestTranslateNetworkRbac_PrefixStartsWith_Allow(t *testing.T) {
	rbac := &sharedv1alpha1.Authorization{
		Policy: sharedv1alpha1.AuthorizationPolicy{
			MatchExpressions: []sharedv1alpha1.CELExpression{
				`source.address.startsWith("10.0.0.")`,
			},
		},
		Action: sharedv1alpha1.AuthorizationPolicyActionAllow,
	}

	objSrc := ir.ObjectSource{Namespace: "test-ns", Name: "test-policy"}

	result, err := translateNetworkRbac(rbac, objSrc)
	require.NoError(t, err)
	require.NotNil(t, result)

	var rbacConfig envoyrbacnetwork.RBAC
	require.NoError(t, result.UnmarshalTo(&rbacConfig))

	assert.Nil(t, rbacConfig.Matcher, "network RBAC must not use the matcher field")
	require.NotNil(t, rbacConfig.Rules)
	assert.Equal(t, envoyrbacv3.RBAC_ALLOW, rbacConfig.Rules.Action)

	policy := rbacConfig.Rules.Policies["network-ip-policy"]
	require.NotNil(t, policy)
	require.Len(t, policy.Principals, 1)

	sourceIP := policy.Principals[0].GetSourceIp()
	require.NotNil(t, sourceIP, "expected Principal.SourceIp")
	assert.Equal(t, "10.0.0.0", sourceIP.AddressPrefix)
	assert.Equal(t, uint32(24), sourceIP.PrefixLen.Value)
}

// TestTranslateNetworkRbac_PrefixStartsWith_Deny verifies deny action with prefix CEL.
func TestTranslateNetworkRbac_PrefixStartsWith_Deny(t *testing.T) {
	rbac := &sharedv1alpha1.Authorization{
		Policy: sharedv1alpha1.AuthorizationPolicy{
			MatchExpressions: []sharedv1alpha1.CELExpression{
				`source.address.startsWith("192.168.0.")`,
			},
		},
		Action: sharedv1alpha1.AuthorizationPolicyActionDeny,
	}

	objSrc := ir.ObjectSource{Namespace: "prod-ns", Name: "deny-policy"}

	result, err := translateNetworkRbac(rbac, objSrc)
	require.NoError(t, err)
	require.NotNil(t, result)

	var rbacConfig envoyrbacnetwork.RBAC
	require.NoError(t, result.UnmarshalTo(&rbacConfig))

	assert.Equal(t, "prod-ns_deny-policy_network_rbac", rbacConfig.StatPrefix)
	assert.Nil(t, rbacConfig.Matcher, "network RBAC must not use the matcher field")
	require.NotNil(t, rbacConfig.Rules)
	assert.Equal(t, envoyrbacv3.RBAC_DENY, rbacConfig.Rules.Action)

	policy := rbacConfig.Rules.Policies["network-ip-policy"]
	require.NotNil(t, policy)
	sourceIP := policy.Principals[0].GetSourceIp()
	require.NotNil(t, sourceIP)
	assert.Equal(t, "192.168.0.0", sourceIP.AddressPrefix)
	assert.Equal(t, uint32(24), sourceIP.PrefixLen.Value)
}

// TestTranslateNetworkRbac_MultipleExpressions verifies OR semantics via Principal_OrIds.
func TestTranslateNetworkRbac_MultipleExpressions(t *testing.T) {
	rbac := &sharedv1alpha1.Authorization{
		Policy: sharedv1alpha1.AuthorizationPolicy{
			MatchExpressions: []sharedv1alpha1.CELExpression{
				`source.address.startsWith("10.0.0.")`,
				`source.address.startsWith("192.168.0.")`,
				`source.address.startsWith("172.16.0.")`,
			},
		},
		Action: sharedv1alpha1.AuthorizationPolicyActionAllow,
	}

	objSrc := ir.ObjectSource{Namespace: "multi-ns", Name: "multi-policy"}

	result, err := translateNetworkRbac(rbac, objSrc)
	require.NoError(t, err)
	require.NotNil(t, result)

	var rbacConfig envoyrbacnetwork.RBAC
	require.NoError(t, result.UnmarshalTo(&rbacConfig))

	assert.Equal(t, "multi-ns_multi-policy_network_rbac", rbacConfig.StatPrefix)
	assert.Nil(t, rbacConfig.Matcher, "network RBAC must not use the matcher field")
	require.NotNil(t, rbacConfig.Rules)
	assert.Equal(t, envoyrbacv3.RBAC_ALLOW, rbacConfig.Rules.Action)

	policy := rbacConfig.Rules.Policies["network-ip-policy"]
	require.NotNil(t, policy)

	// Multiple CIDRs are combined via OrIds on a single Principal wrapper.
	require.Len(t, policy.Principals, 1, "multiple CIDRs should be wrapped in a single OrIds principal")
	orIds := policy.Principals[0].GetOrIds()
	require.NotNil(t, orIds, "expected Principal.OrIds for multiple CIDRs")
	assert.Len(t, orIds.Ids, 3)

	// Verify each inner principal is a SourceIp.
	for _, p := range orIds.Ids {
		assert.NotNil(t, p.GetSourceIp(), "each OR element should be a Principal.SourceIp")
	}
}

// TestTranslateNetworkRbac_CIDRLiteral verifies direct CIDR notation in == expressions.
func TestTranslateNetworkRbac_CIDRLiteral(t *testing.T) {
	rbac := &sharedv1alpha1.Authorization{
		Policy: sharedv1alpha1.AuthorizationPolicy{
			MatchExpressions: []sharedv1alpha1.CELExpression{
				`source.address == "10.0.0.0/24"`,
			},
		},
		Action: sharedv1alpha1.AuthorizationPolicyActionAllow,
	}

	objSrc := ir.ObjectSource{Namespace: "test-ns", Name: "cidr-policy"}

	result, err := translateNetworkRbac(rbac, objSrc)
	require.NoError(t, err)
	require.NotNil(t, result)

	var rbacConfig envoyrbacnetwork.RBAC
	require.NoError(t, result.UnmarshalTo(&rbacConfig))

	policy := rbacConfig.Rules.Policies["network-ip-policy"]
	require.NotNil(t, policy)
	sourceIP := policy.Principals[0].GetSourceIp()
	require.NotNil(t, sourceIP)
	assert.Equal(t, "10.0.0.0", sourceIP.AddressPrefix)
	assert.Equal(t, uint32(24), sourceIP.PrefixLen.Value)
}

// TestTranslateNetworkRbac_UnsupportedCEL verifies that CEL expressions that
// cannot be mapped to connection-level CIDR matching produce a clear error,
// rather than generating invalid Envoy config that is silently rejected.
func TestTranslateNetworkRbac_UnsupportedCEL(t *testing.T) {
	cases := []struct {
		name string
		expr sharedv1alpha1.CELExpression
	}{
		{
			name: "http header attribute",
			expr: `request.headers["x-custom"] == "value"`,
		},
		{
			name: "arbitrary CEL function",
			expr: `source.address.contains("10.0")`,
		},
		{
			name: "invalid syntax",
			expr: `invalid CEL syntax!!!`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rbac := &sharedv1alpha1.Authorization{
				Policy: sharedv1alpha1.AuthorizationPolicy{
					MatchExpressions: []sharedv1alpha1.CELExpression{tc.expr},
				},
				Action: sharedv1alpha1.AuthorizationPolicyActionAllow,
			}

			_, err := translateNetworkRbac(rbac, ir.ObjectSource{Namespace: "test-ns", Name: "bad-policy"})
			require.Error(t, err, "unsupported CEL expression must return an error")
			assert.Contains(t, err.Error(), "only IP/CIDR expressions are supported at the network layer")
		})
	}
}

// MARK: - parseCIDRFromCEL unit tests

func TestParseCIDRFromCEL(t *testing.T) {
	cases := []struct {
		expr       string
		wantCIDR   string
		wantErrSub string
	}{
		// Exact IP (IPv4)
		{expr: `source.address == "10.0.0.1"`, wantCIDR: "10.0.0.1/32"},
		// Exact CIDR literal
		{expr: `source.address == "10.0.0.0/24"`, wantCIDR: "10.0.0.0/24"},
		// startsWith – 1 octet
		{expr: `source.address.startsWith("10.")`, wantCIDR: "10.0.0.0/8"},
		// startsWith – 2 octets
		{expr: `source.address.startsWith("192.168.")`, wantCIDR: "192.168.0.0/16"},
		// startsWith – 3 octets
		{expr: `source.address.startsWith("172.16.0.")`, wantCIDR: "172.16.0.0/24"},
		// Unsupported: HTTP attribute
		{expr: `request.headers["x-foo"] == "bar"`, wantErrSub: "is not supported in network RBAC"},
		// Unsupported: arbitrary function
		{expr: `source.address.endsWith(".1")`, wantErrSub: "is not supported in network RBAC"},
	}

	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got, err := parseCIDRFromCEL(tc.expr)
			if tc.wantErrSub != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSub)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantCIDR, got)
			}
		})
	}
}

// MARK: - buildPrincipalsFromCIDRs unit tests

func TestBuildPrincipalsFromCIDRs(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		principals, err := buildPrincipalsFromCIDRs(nil)
		require.NoError(t, err)
		assert.Empty(t, principals)
	})

	t.Run("single", func(t *testing.T) {
		principals, err := buildPrincipalsFromCIDRs([]string{"10.0.0.0/8"})
		require.NoError(t, err)
		require.Len(t, principals, 1)
		sourceIP := principals[0].GetSourceIp()
		require.NotNil(t, sourceIP)
		assert.Equal(t, "10.0.0.0", sourceIP.AddressPrefix)
		assert.Equal(t, uint32(8), sourceIP.PrefixLen.Value)
	})

	t.Run("multiple → OrIds", func(t *testing.T) {
		principals, err := buildPrincipalsFromCIDRs([]string{"10.0.0.0/8", "192.168.0.0/16"})
		require.NoError(t, err)
		require.Len(t, principals, 1)
		orIds := principals[0].GetOrIds()
		require.NotNil(t, orIds)
		assert.Len(t, orIds.Ids, 2)
		for _, p := range orIds.Ids {
			assert.NotNil(t, p.GetSourceIp())
		}
	})

	t.Run("invalid CIDR returns error", func(t *testing.T) {
		_, err := buildPrincipalsFromCIDRs([]string{"not-a-cidr"})
		require.Error(t, err)
	})
}


