// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package service

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// fakeLink builds a minimal netlink.Link with the given name/index/flags.
func fakeLink(name string, index int, flags net.Flags) netlink.Link {
	return &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{
		Name:  name,
		Index: index,
		Flags: flags,
	}}
}

func swapEnsureReadySeams(t *testing.T) {
	t.Helper()
	oldByName := netlinkLinkByName
	oldSetUp := netlinkLinkSetUp
	t.Cleanup(func() {
		netlinkLinkByName = oldByName
		netlinkLinkSetUp = oldSetUp
	})
}

func TestEnsureTapLinkReadyPassesThroughHealthyUpTap(t *testing.T) {
	swapEnsureReadySeams(t)
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return fakeLink(name, 13, net.FlagUp), nil
	}
	setUpCalls := 0
	netlinkLinkSetUp = func(netlink.Link) error { setUpCalls++; return nil }

	idx, err := ensureTapLinkReady("z192.168.0.3", 13)
	if err != nil {
		t.Fatalf("ensureTapLinkReady error=%v", err)
	}
	if idx != 13 {
		t.Fatalf("ifindex=%d, want 13", idx)
	}
	if setUpCalls != 0 {
		t.Fatalf("LinkSetUp called %d times on an already-UP tap, want 0", setUpCalls)
	}
}

func TestEnsureTapLinkReadyBringsDownTapUp(t *testing.T) {
	// An admin-DOWN tap is the exact device state that turns the guest's first
	// TX into a fatal EIO. The verification must repair it in place.
	swapEnsureReadySeams(t)
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return fakeLink(name, 13, 0), nil // down
	}
	setUpCalls := 0
	netlinkLinkSetUp = func(netlink.Link) error { setUpCalls++; return nil }

	idx, err := ensureTapLinkReady("z192.168.0.3", 13)
	if err != nil {
		t.Fatalf("ensureTapLinkReady error=%v", err)
	}
	if idx != 13 {
		t.Fatalf("ifindex=%d, want 13", idx)
	}
	if setUpCalls != 1 {
		t.Fatalf("LinkSetUp calls=%d, want 1", setUpCalls)
	}
}

func TestEnsureTapLinkReadyRejectsDeletedTap(t *testing.T) {
	// A deleted tap must be a NAMED error — never a silent TUNSETIFF
	// resurrection of an unconfigured device.
	swapEnsureReadySeams(t)
	netlinkLinkByName = func(string) (netlink.Link, error) {
		return nil, errors.New("Link not found")
	}
	netlinkLinkSetUp = func(netlink.Link) error {
		t.Fatal("LinkSetUp must not be called for a deleted tap")
		return nil
	}

	_, err := ensureTapLinkReady("z192.168.0.3", 13)
	if err == nil {
		t.Fatal("expected an error for a deleted tap")
	}
	if !strings.Contains(err.Error(), "deleted out-of-band") {
		t.Fatalf("error should name the out-of-band deletion, got: %v", err)
	}
}

func TestEnsureTapLinkReadyRejectsRecreatedTap(t *testing.T) {
	// Same name, different ifindex = the device was deleted and re-created by
	// someone else; none of our configuration (TC filter, MTU, ARP) is on it.
	swapEnsureReadySeams(t)
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return fakeLink(name, 99, net.FlagUp), nil
	}
	_, err := ensureTapLinkReady("z192.168.0.3", 13)
	if err == nil {
		t.Fatal("expected an error for a re-created tap")
	}
	if !strings.Contains(err.Error(), "re-created out-of-band") {
		t.Fatalf("error should name the re-creation, got: %v", err)
	}
}

func TestEnsureTapLinkReadyAdoptsIndexWhenUnknown(t *testing.T) {
	// expectIfindex 0 = state restored without an index (e.g. after an agent
	// restart); the verified kernel index must be adopted, not rejected.
	swapEnsureReadySeams(t)
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return fakeLink(name, 42, net.FlagUp), nil
	}
	idx, err := ensureTapLinkReady("z192.168.0.3", 0)
	if err != nil {
		t.Fatalf("ensureTapLinkReady error=%v", err)
	}
	if idx != 42 {
		t.Fatalf("ifindex=%d, want 42", idx)
	}
}

func TestEnsureTapLinkReadySurfacesLinkSetUpFailure(t *testing.T) {
	swapEnsureReadySeams(t)
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return fakeLink(name, 13, 0), nil // down
	}
	netlinkLinkSetUp = func(netlink.Link) error { return errors.New("EPERM") }

	_, err := ensureTapLinkReady("z192.168.0.3", 13)
	if err == nil {
		t.Fatal("expected an error when LinkSetUp fails")
	}
	if !strings.Contains(err.Error(), "LinkSetUp failed") {
		t.Fatalf("error should name the SetUp failure, got: %v", err)
	}
}

func TestGetTapFileRefusesUnreadyTap(t *testing.T) {
	// GetTapFile must fail FAST with the verification error and must NOT fall
	// through to openTapFdByName (whose TUNSETIFF would resurrect a deleted
	// name as a dead, unconfigured device — a zombie the guest then dies on).
	oldEnsureReady := ensureTapLinkReadyFunc
	oldOpen := openTapFdByNameFunc
	oldRestore := restoreTapFunc
	t.Cleanup(func() {
		ensureTapLinkReadyFunc = oldEnsureReady
		openTapFdByNameFunc = oldOpen
		restoreTapFunc = oldRestore
	})
	ensureTapLinkReadyFunc = func(string, int) (int, error) {
		return 0, errors.New(`tap "z192.168.0.3" is gone from the kernel (deleted out-of-band?)`)
	}
	openTapFdByNameFunc = func(string) (*os.File, error) {
		t.Fatal("openTapFdByName must not run for an unready tap")
		return nil, nil
	}
	restoreTapFunc = func(tap *tapDevice, _ int, _ string, _ int) (*tapDevice, error) {
		t.Fatal("restoreTap must not run for an unready tap")
		return nil, nil
	}

	svc := &localService{states: map[string]*managedState{
		"sandbox-1": {persistedState: persistedState{
			SandboxID:  "sandbox-1",
			TapName:    "z192.168.0.3",
			TapIfIndex: 13,
			SandboxIP:  "192.168.0.3",
		}},
	}}
	_, _, err := svc.GetTapFile("sandbox-1", "z192.168.0.3")
	if err == nil {
		t.Fatal("expected GetTapFile to fail for an unready tap")
	}
	if !strings.Contains(err.Error(), "tap not ready for sandbox") {
		t.Fatalf("error should be the named verification failure, got: %v", err)
	}
}
