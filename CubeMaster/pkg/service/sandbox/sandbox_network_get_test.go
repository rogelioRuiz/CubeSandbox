// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/errorcode"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/service/sandbox/types"
	cubebox "github.com/tencentcloud/CubeSandbox/pkgs/proto/services/cubebox/v1"
)

// TestMapCubeNetworkConfigFromCubeletRoundTrips pins the read-back mapper
// against the write mapper: a policy that goes to a node and comes back must
// be the same policy, or the endpoint would misreport what is installed.
func TestMapCubeNetworkConfigFromCubeletRoundTrips(t *testing.T) {
	allowInternetAccess := false
	host := "api.example.com"
	scheme := "https"
	port := 8443
	audit := "full"
	format := "Bearer %s"
	in := &types.CubeNetworkConfig{
		AllowInternetAccess: &allowInternetAccess,
		AllowOut:            []string{"1.1.1.1/32", "api.example.com"},
		DenyOut:             []string{"10.0.0.0/8"},
		Rules: []*types.EgressRule{{
			Name: "api",
			Match: &types.EgressRuleMatch{
				Host:   &host,
				Method: []string{"GET"},
				Scheme: &scheme,
				Port:   &port,
			},
			Action: &types.EgressRuleAction{
				Allow: true,
				Audit: &audit,
				Inject: []*types.EgressRuleInject{{
					Header: "authorization",
					Secret: "token",
					Format: &format,
				}},
			},
		}},
	}

	out := mapCubeNetworkConfigFromCubelet(mapCubeNetworkConfig(in))
	assert.Equal(t, in, out)
}

func TestMapCubeNetworkConfigFromCubeletNil(t *testing.T) {
	assert.Nil(t, mapCubeNetworkConfigFromCubelet(nil))
}

// TestMapCubeNetworkConfigFromCubeletKeepsUnsetInternetAccess pins the
// tri-state: "not set" must not collapse into false, which would report every
// default-open sandbox as internet-blocked.
func TestMapCubeNetworkConfigFromCubeletKeepsUnsetInternetAccess(t *testing.T) {
	out := mapCubeNetworkConfigFromCubelet(&cubebox.CubeNetworkConfig{AllowOut: []string{"1.1.1.1/32"}})
	require.NotNil(t, out)
	assert.Nil(t, out.AllowInternetAccess)
}

func TestGetNetworkRejectsEmptySandboxID(t *testing.T) {
	rsp := GetNetwork(context.Background(), &types.GetNetworkRequest{RequestID: "req-1"})
	require.NotNil(t, rsp.Ret)
	assert.Equal(t, int(errorcode.ErrorCode_MasterParamsError), rsp.Ret.RetCode)
	assert.Empty(t, rsp.Source)
}
