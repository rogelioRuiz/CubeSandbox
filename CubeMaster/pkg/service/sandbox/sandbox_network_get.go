// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package sandbox

import (
	"context"

	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/cubelet"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/errorcode"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/service/sandbox/types"
	"github.com/tencentcloud/CubeSandbox/pkgs/proto/services/cubebox/v1"
)

// networkSourceNode marks a policy read that came from the node running the
// sandbox rather than from the stored create spec.
const networkSourceNode = "node"

// GetNetwork implements GET /cube/sandbox/network: it returns the egress
// policy the sandbox is running under and the datapath policy generation.
//
// The read goes to the node, never to sandboxspec. The spec write on the
// update path is best effort, so a spec-only answer could describe a policy
// the datapath never accepted -- the exact confusion this endpoint exists to
// remove. Generation lets a caller prove an update landed: it advances on
// every accepted policy change.
//
// No lifecycle lock is taken here. The node serializes the read against its
// own policy updates, and holding the master-side lock would let a read block
// behind a pause that is packaging the sandbox.
func GetNetwork(ctx context.Context, req *types.GetNetworkRequest) (rsp *types.GetNetworkRes) {
	rsp = &types.GetNetworkRes{
		RequestID: req.RequestID,
		SandboxID: req.SandboxID,
		Ret: &types.Ret{
			RetCode: int(errorcode.ErrorCode_Success),
			RetMsg:  errorcode.ErrorCode_Success.String(),
		},
	}
	if req.SandboxID == "" {
		rsp.Ret.RetCode = int(errorcode.ErrorCode_MasterParamsError)
		rsp.Ret.RetMsg = "should provide SandboxID"
		return
	}
	if r := normalizeSandboxIDInReq(ctx, &req.SandboxID); r != nil {
		rsp.Ret = r
		rsp.SandboxID = req.SandboxID
		return
	}
	rsp.SandboxID = req.SandboxID

	hostIP, ok := resolveSandboxHostIP(ctx, req.SandboxID)
	if !ok {
		rsp.Ret.RetCode = int(errorcode.ErrorCode_NotFound)
		rsp.Ret.RetMsg = "sandbox not found"
		return
	}

	cubeRsp, err := cubelet.GetSandboxNetwork(ctx, cubelet.GetCubeletAddr(hostIP), &cubebox.GetSandboxNetworkRequest{
		RequestID: req.RequestID,
		SandboxID: req.SandboxID,
	})
	if err != nil || cubeRsp.GetRet() == nil {
		msg := "cubelet get network response is nil"
		if err != nil {
			msg = err.Error()
		}
		rsp.Ret.RetCode = int(errorcode.ErrorCode_ReqCubeAPIFailed)
		rsp.Ret.RetMsg = msg
		return
	}
	rsp.Ret.RetCode = int(cubeRsp.GetRet().GetRetCode())
	rsp.Ret.RetMsg = cubeRsp.GetRet().GetRetMsg()
	if rsp.Ret.RetCode != int(errorcode.ErrorCode_Success) {
		return
	}
	rsp.CubeNetworkConfig = mapCubeNetworkConfigFromCubelet(cubeRsp.GetCubeNetworkConfig())
	rsp.Generation = cubeRsp.GetGeneration()
	rsp.Source = networkSourceNode
	return
}
