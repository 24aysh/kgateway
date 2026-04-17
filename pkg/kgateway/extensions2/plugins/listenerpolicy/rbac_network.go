package listenerpolicy

import (
	"fmt"
	"net"
	"strings"

	envoycorev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyrbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	envoyrbacnetwork "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/rbac/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	sharedv1alpha1 "github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"
	"github.com/kgateway-dev/kgateway/v2/pkg/kgateway/utils"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/ir"
)

// translateNetworkRbac converts shared.Authorization to an Envoy network RBAC filter config.
//
// The network RBAC filter runs at the L4 connection level (before HTTP parsing).
// Therefore it only supports connection-level attributes such as source IP/CIDR.
// Arbitrary HTTP-level CEL matchers (HttpAttributesCelMatchInput) are NOT valid here
// and will cause Envoy to reject the listener update at runtime.
//
// Supported CEL patterns:
//   - source.address == "1.2.3.4"           → exact host /32 CIDR
//   - source.address.startsWith("10.0.0.")  → prefix-derived CIDR (e.g. /24)
//
// Any expression that does not match one of the above patterns is rejected with
// an error rather than silently producing invalid Envoy configuration.
func translateNetworkRbac(rbac *sharedv1alpha1.Authorization, objSrc ir.ObjectSource) (*anypb.Any, error) {
	if rbac == nil {
		return nil, nil
	}

	statPrefix := fmt.Sprintf("%s_%s_network_rbac", objSrc.Namespace, objSrc.Name)

	// No match expressions → deny-all: ALLOW action with empty policy set.
	if len(rbac.Policy.MatchExpressions) == 0 {
		rbacConfig := &envoyrbacnetwork.RBAC{
			StatPrefix: statPrefix,
			Rules: &envoyrbacv3.RBAC{
				Action:   envoyrbacv3.RBAC_DENY,
				Policies: map[string]*envoyrbacv3.Policy{},
			},
		}
		return utils.MessageToAny(rbacConfig)
	}

	// Parse each CEL expression into a CIDR range string.
	var cidrs []string
	var errs []error
	for _, expr := range rbac.Policy.MatchExpressions {
		cidr, err := parseCIDRFromCEL(string(expr))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cidrs = append(cidrs, cidr)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("CEL matcher errors in network RBAC policy (only IP/CIDR expressions are supported at the network layer): %v", errs)
	}

	// Build a Principal per CIDR, combined with OR semantics.
	principals, err := buildPrincipalsFromCIDRs(cidrs)
	if err != nil {
		return nil, fmt.Errorf("failed to build principals from CIDRs: %w", err)
	}

	action := envoyrbacv3.RBAC_ALLOW
	if rbac.Action == sharedv1alpha1.AuthorizationPolicyActionDeny {
		action = envoyrbacv3.RBAC_DENY
	}

	rbacConfig := &envoyrbacnetwork.RBAC{
		StatPrefix: statPrefix,
		Rules: &envoyrbacv3.RBAC{
			Action: action,
			Policies: map[string]*envoyrbacv3.Policy{
				"network-ip-policy": {
					// Allow any permission (we restrict by principal/source IP only).
					Permissions: []*envoyrbacv3.Permission{
						{Rule: &envoyrbacv3.Permission_Any{Any: true}},
					},
					Principals: principals,
				},
			},
		},
	}

	return utils.MessageToAny(rbacConfig)
}

// parseCIDRFromCEL converts a limited set of CEL expressions into a CIDR string.
//
// Supported forms:
//
//	source.address == "1.2.3.4"          → "1.2.3.4/32"
//	source.address == "1.2.3.4/24"       → "1.2.3.4/24"  (CIDR literal)
//	source.address.startsWith("10.0.0.") → "10.0.0.0/24"
func parseCIDRFromCEL(expr string) (string, error) {
	expr = strings.TrimSpace(expr)

	// Pattern: source.address == "..."
	if cidr, ok := parseEqualsExpr(expr); ok {
		return cidr, nil
	}

	// Pattern: source.address.startsWith("...")
	if cidr, ok := parsePrefixExpr(expr); ok {
		return cidr, nil
	}

	return "", fmt.Errorf(
		"expression %q is not supported in network RBAC; "+
			"use 'source.address == \"<IP>\"' or 'source.address.startsWith(\"<prefix>\")'",
		expr,
	)
}

// parseEqualsExpr handles: source.address == "1.2.3.4" or source.address == "1.2.3.0/24"
func parseEqualsExpr(expr string) (string, bool) {
	const prefix = `source.address == "`
	if !strings.HasPrefix(expr, prefix) {
		return "", false
	}
	rest := expr[len(prefix):]
	if !strings.HasSuffix(rest, `"`) {
		return "", false
	}
	val := rest[:len(rest)-1]

	// Already a CIDR?
	if _, _, err := net.ParseCIDR(val); err == nil {
		return val, true
	}

	// Plain IP → /32 (IPv4) or /128 (IPv6)
	ip := net.ParseIP(val)
	if ip == nil {
		return "", false
	}
	if ip.To4() != nil {
		return val + "/32", true
	}
	return val + "/128", true
}

// parsePrefixExpr handles: source.address.startsWith("10.0.0.")
// It derives the CIDR from the dotted-octet prefix length.
func parsePrefixExpr(expr string) (string, bool) {
	const prefix = `source.address.startsWith("`
	if !strings.HasPrefix(expr, prefix) {
		return "", false
	}
	rest := expr[len(prefix):]
	if !strings.HasSuffix(rest, `")`) {
		return "", false
	}
	dotPrefix := rest[:len(rest)-2] // e.g. "10.0.0."

	// Count octets in the prefix to determine the CIDR length.
	// Remove trailing dot if present for counting.
	parts := strings.Split(strings.TrimSuffix(dotPrefix, "."), ".")
	if len(parts) == 0 || len(parts) > 3 {
		return "", false
	}

	// Pad to 4 octets with zeros.
	padded := make([]string, 4)
	copy(padded, parts)
	for i := len(parts); i < 4; i++ {
		padded[i] = "0"
	}

	ip := strings.Join(padded, ".")
	if net.ParseIP(ip) == nil {
		return "", false
	}

	prefixLen := len(parts) * 8
	cidr := fmt.Sprintf("%s/%d", ip, prefixLen)
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return "", false
	}
	return cidr, true
}

// buildPrincipalsFromCIDRs creates a slice of Envoy Principals from CIDR strings.
// Multiple CIDRs are combined with OR semantics using Principal_OrIds.
func buildPrincipalsFromCIDRs(cidrs []string) ([]*envoyrbacv3.Principal, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}

	var cidrPrincipals []*envoyrbacv3.Principal
	for _, cidr := range cidrs {
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		_ = ip

		ones, _ := ipNet.Mask.Size()
		cidrPrincipals = append(cidrPrincipals, &envoyrbacv3.Principal{
			Identifier: &envoyrbacv3.Principal_SourceIp{
				SourceIp: &envoycorev3.CidrRange{
					AddressPrefix: ipNet.IP.String(),
					PrefixLen:     &wrapperspb.UInt32Value{Value: uint32(ones)}, //nolint:gosec // prefix len bounded 0-128
				},
			},
		})
	}

	if len(cidrPrincipals) == 1 {
		return cidrPrincipals, nil
	}

	// Multiple CIDRs → OR semantics via Principal_OrIds.
	return []*envoyrbacv3.Principal{
		{
			Identifier: &envoyrbacv3.Principal_OrIds{
				OrIds: &envoyrbacv3.Principal_Set{
					Ids: cidrPrincipals,
				},
			},
		},
	}, nil
}
