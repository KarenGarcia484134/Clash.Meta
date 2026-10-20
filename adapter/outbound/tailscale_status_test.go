//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func newTestTailscale(t *testing.T, option TailscaleOption) *Tailscale {
	t.Helper()
	if option.Name == "" {
		option.Name = "ts"
	}
	if option.StateDir == "" {
		option.StateDir = "tailscale/test"
	}
	node, err := NewTailscale(option)
	if err != nil {
		t.Skipf("tailscale outbound unavailable: %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "ts-home")
	if err != nil {
		panic(err)
	}
	C.SetHomeDir(home)
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}

func TestTailscaleStatusBeforeStart(t *testing.T) {
	node := &Tailscale{}
	if node.Started() {
		t.Fatal("a fresh node must not report started")
	}
	if _, err := node.Status(context.Background()); !errors.Is(err, ErrTailscaleNotStarted) {
		t.Fatalf("expected ErrTailscaleNotStarted, got %v", err)
	}
}

func TestUnwrapTailscaleThroughAutoClose(t *testing.T) {
	node := newTestTailscale(t, TailscaleOption{})
	got, ok := UnwrapTailscale(NewAutoCloseProxyAdapter(node))
	if !ok || got != node {
		t.Fatal("the parser's auto-close wrapper must unwrap to the node")
	}
	if _, ok := UnwrapTailscale(nil); ok {
		t.Fatal("nil must not unwrap")
	}
}

func TestTailscaleSameConfig(t *testing.T) {
	dir := "tailscale/same"
	yes := true
	a := newTestTailscale(t, TailscaleOption{StateDir: dir, AuthKey: "k", AcceptRoutes: &yes})
	b := newTestTailscale(t, TailscaleOption{StateDir: dir, AuthKey: "k", AcceptRoutes: &yes})
	c := newTestTailscale(t, TailscaleOption{StateDir: dir, AuthKey: "other"})
	if !a.SameConfig(b) {
		t.Fatal("identical options must match")
	}
	if a.SameConfig(c) || a.SameConfig(nil) {
		t.Fatal("different options must not match")
	}
}

func TestTailscaleSettled(t *testing.T) {
	for _, tc := range []struct {
		state, url string
		want       bool
	}{
		{"NoState", "", false},
		{"Starting", "", false},
		{"NeedsLogin", "", false},
		{"NeedsLogin", "https://login.tailscale.com/a/x", true},
		{"NeedsMachineAuth", "", true},
		{"Running", "", true},
		{"Stopped", "", true},
	} {
		if got := TailscaleSettled(tc.state, tc.url); got != tc.want {
			t.Errorf("TailscaleSettled(%q, %q) = %v, want %v", tc.state, tc.url, got, tc.want)
		}
	}
}

func TestTailscaleWaitAndPingBeforeStart(t *testing.T) {
	node := &Tailscale{}
	if _, _, err := node.WaitSettled(context.Background()); !errors.Is(err, ErrTailscaleNotStarted) {
		t.Fatalf("expected ErrTailscaleNotStarted, got %v", err)
	}
	if _, err := node.Ping(context.Background(), netip.MustParseAddr("100.64.0.1"), "disco"); !errors.Is(err, ErrTailscaleNotStarted) {
		t.Fatalf("expected ErrTailscaleNotStarted, got %v", err)
	}
}

func TestTailscaleNetworkChangedBeforeStart(t *testing.T) {
	(&Tailscale{}).NetworkChanged()
	newTestTailscale(t, TailscaleOption{}).NetworkChanged()
}
