// Copyright (c) 2024 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package service

import (
	"context"
	"fmt"
	"net"
	"os"

	CubeLog "github.com/tencentcloud/CubeSandbox/cubelog"
)

// TapFDProvider exposes the original TAP fd owned by network-agent. It also
// returns the tap's kernel ifindex so callers (cubelet) can avoid a separate
// netlink LinkByName lookup on the create hot path.
type TapFDProvider interface {
	GetTapFile(sandboxID, tapName string) (*os.File, int, error)
}

// ensureTapLinkReadyFunc is swappable for tests.
var ensureTapLinkReadyFunc = ensureTapLinkReady

// ensureTapLinkReady confirms the tap netdevice still exists, is the device we
// configured (same ifindex) and is administratively UP, bringing it up when it
// is not. It returns the verified kernel ifindex.
//
// Without this check, an out-of-band `ip link del` of a managed tap goes
// unnoticed: TUNSETIFF on the deleted name does not fail, it silently creates
// a fresh admin-DOWN device with none of our configuration (no TC filter,
// wrong MTU, no ARP entry). The guest then boots against a dead tap and its
// first TX fails with EIO, which the hypervisor treats as fatal. A guest
// resumed from a memory snapshot transmits within ~300ms, so the window is
// hit routinely. Cost: one netlink read per sandbox create, not per packet.
func ensureTapLinkReady(tapName string, expectIfindex int) (int, error) {
	link, err := netlinkLinkByName(tapName)
	if err != nil {
		return 0, fmt.Errorf("tap %q is gone from the kernel (deleted out-of-band?): %w", tapName, err)
	}
	attrs := link.Attrs()
	if expectIfindex > 0 && attrs.Index != expectIfindex {
		return 0, fmt.Errorf(
			"tap %q was re-created out-of-band (ifindex %d, expected %d) — its qdisc filter/MTU/ARP configuration can no longer be trusted",
			tapName, attrs.Index, expectIfindex,
		)
	}
	if attrs.Flags&net.FlagUp == 0 {
		if err := netlinkLinkSetUp(link); err != nil {
			return 0, fmt.Errorf("tap %q is admin-DOWN and LinkSetUp failed: %w", tapName, err)
		}
		CubeLog.WithContext(context.Background()).Warnf(
			"network-agent ensureTapLinkReady: tap %q was admin-DOWN; brought it UP before fd handoff",
			tapName,
		)
	}
	return attrs.Index, nil
}

func (s *localService) GetTapFile(sandboxID, tapName string) (*os.File, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.states[sandboxID]
	if !ok {
		return nil, 0, fmt.Errorf("sandbox %q not found", sandboxID)
	}
	if tapName != "" && state.TapName != tapName {
		return nil, 0, fmt.Errorf("tap name mismatch: want %q got %q", tapName, state.TapName)
	}

	// Every handoff path below assumes the netdevice still exists, is ours and
	// is UP. Verify that once up front (see ensureTapLinkReady) so a violated
	// assumption fails the create with the real reason instead of booting a
	// guest against a dead tap.
	verifiedIfindex, err := ensureTapLinkReadyFunc(state.TapName, state.TapIfIndex)
	if err != nil {
		return nil, 0, fmt.Errorf("tap not ready for sandbox %q: %w", sandboxID, err)
	}
	if state.TapIfIndex == 0 {
		state.TapIfIndex = verifiedIfindex
	}

	ifindex := state.TapIfIndex

	// Fast path: the fd is already cached, return it with no further syscalls.
	if state.tap != nil && state.tap.File != nil {
		return state.tap.File, indexFallback(ifindex, state.tap), nil
	}

	// Hot path: an in-process managed tap that is fully configured but whose fd
	// was closed while it sat idle in the pool. The device was just verified
	// above (exists, ours, UP), so we only need to re-open the fd: the MTU, TC
	// filter and ARP entry were applied when the tap was created and survive an
	// fd close. We skip the full restoreTap and issue the cheap open + TUNSETIFF.
	//
	// We keep this under s.mu on purpose: parallelising these syscalls across
	// concurrent sandbox boots regressed tail latency (they contend on kernel
	// locks anyway), so an orderly short critical section is preferable.
	if state.tap != nil && !state.tap.InUse {
		file, err := openTapFdByNameFunc(state.TapName)
		if err == nil {
			state.tap.File = file
			return state.tap.File, indexFallback(ifindex, state.tap), nil
		}
		// On a transient open failure (e.g. the kernel is momentarily busy) we
		// deliberately do NOT fail the request: fall through to the recovery
		// path below so restoreTap can re-validate and retry the fd acquisition,
		// letting the request self-heal instead of propagating a sandbox-create
		// failure to the caller. We log at WARN so a SYSTEMATIC fast-path failure
		// (e.g. a regression in openTapFdByName) is loud here instead of silently
		// degrading every request to the slow restoreTap path.
		CubeLog.WithContext(context.Background()).Warnf(
			"network-agent GetTapFile fast reopen failed, falling back to restoreTap: sandbox_id=%s tap=%s err=%v",
			sandboxID, state.TapName, err,
		)
	}

	// Recovery path: no in-memory tap (e.g. after a restart) or the tap is held
	// by another process. Fall back to the full restore which probes the kernel
	// state and only acquires the fd when the tap is idle.
	baseTap := state.tap
	if baseTap == nil {
		baseTap = &tapDevice{
			Name:         state.TapName,
			IP:           net.ParseIP(state.SandboxIP).To4(),
			PortMappings: append([]PortMapping(nil), state.PortMappings...),
		}
	} else {
		baseTap.PortMappings = append([]PortMapping(nil), state.PortMappings...)
	}
	tap, err := restoreTapFunc(baseTap, s.cfg.MvmMtu, s.cfg.MVMMacAddr, s.cubeDev.Index)
	if err != nil {
		return nil, 0, fmt.Errorf("tap fd unavailable for sandbox %q: %w", sandboxID, err)
	}
	state.tap = tap
	// restoreTap intentionally skips fd acquisition when the tap is held by
	// another process. If we still have no fd at this point, surface a clear
	// error rather than handing back a nil file.
	if state.tap.File == nil {
		return nil, 0, fmt.Errorf("tap fd unavailable for sandbox %q: tap %s is currently held by another process", sandboxID, state.TapName)
	}
	return state.tap.File, indexFallback(ifindex, state.tap), nil
}

// indexFallback prefers the persisted ifindex and falls back to the live tap's
// index when the persisted value is unset (0).
func indexFallback(persisted int, tap *tapDevice) int {
	if persisted != 0 {
		return persisted
	}
	if tap != nil {
		return tap.Index
	}
	return 0
}
