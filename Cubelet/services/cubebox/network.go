// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package cubebox

import (
	"context"
	"strings"

	"github.com/tencentcloud/CubeSandbox/Cubelet/network"
	"github.com/tencentcloud/CubeSandbox/Cubelet/api/services/cubebox/v1"
	"github.com/tencentcloud/CubeSandbox/Cubelet/api/services/errorcode/v1"
)

// GetSandboxNetwork returns the egress policy this node has installed for a
// sandbox plus the datapath policy generation.
//
// It reads the node's own network state rather than any stored create spec:
// the spec write on the update path is best effort, so only the node can say
// what packets are actually judged against. A sandbox whose network is gone
// reports Conflict, the same condition the update path maps that way.
func (s *service) GetSandboxNetwork(ctx context.Context, req *cubebox.GetSandboxNetworkRequest) (*cubebox.GetSandboxNetworkResponse, error) {
	rsp := &cubebox.GetSandboxNetworkResponse{
		RequestID: req.GetRequestID(),
		SandboxID: strings.TrimSpace(req.GetSandboxID()),
		Ret:       &errorcode.Ret{RetCode: errorcode.ErrorCode_Success},
	}
	if rsp.SandboxID == "" {
		rsp.Ret.RetCode = errorcode.ErrorCode_InvalidParamFormat
		rsp.Ret.RetMsg = "must provide sandboxID"
		return rsp, nil
	}

	cfg, generation, err := network.GetSandboxNetworkPolicy(ctx, rsp.SandboxID)
	if err != nil {
		rsp.Ret.RetMsg = err.Error()
		if network.IsSandboxNetworkNotActive(err) {
			rsp.Ret.RetCode = errorcode.ErrorCode_Conflict
		} else {
			rsp.Ret.RetCode = errorcode.ErrorCode_Unknown
		}
		return rsp, nil
	}
	rsp.CubeNetworkConfig = cfg
	rsp.Generation = generation
	return rsp, nil
}
