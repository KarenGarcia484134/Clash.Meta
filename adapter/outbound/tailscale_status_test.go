//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net"
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

func TestTailscaleNeedsReconnect(t *testing.T) {
	for _, tc := range []struct {
		state, url string
		want       bool
	}{
		{"NeedsLogin", "", true},
		{"NeedsLogin", "https://login.tailscale.com/a/x", false},
		{"NoState", "", true},
		{"Starting", "", true},
		{"Running", "", false},
		{"Stopped", "", false},
		{"NeedsMachineAuth", "", false},
	} {
		if got := TailscaleNeedsReconnect(tc.state, tc.url); got != tc.want {
			t.Errorf("TailscaleNeedsReconnect(%q, %q) = %v, want %v", tc.state, tc.url, got, tc.want)
		}
	}
	if err := (&Tailscale{}).Reconnect(context.Background()); !errors.Is(err, ErrTailscaleNotStarted) {
		t.Fatalf("expected ErrTailscaleNotStarted, got %v", err)
	}
}

// The node's control dial must go through its dialer-proxy and never fall
// back to dialing directly, which a censored network resets.
func TestTailscaleSystemDialerKeepsDialerProxy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	direct := newTestTailscale(t, TailscaleOption{StateDir: "tailscale/direct"})
	if direct.DialerProxy() != "" {
		t.Fatal("no dialer-proxy means direct")
	}
	conn, err := direct.server.SystemDialer(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("a node without dialer-proxy dials directly: %v", err)
	}
	_ = conn.Close()

	via := newTestTailscale(t, TailscaleOption{
		StateDir:    "tailscale/via",
		BasicOption: BasicOption{DialerProxy: "missing-group"},
	})
	if via.DialerProxy() != "missing-group" {
		t.Fatalf("DialerProxy() = %q", via.DialerProxy())
	}
	if conn, err := via.server.SystemDialer(context.Background(), "tcp", listener.Addr().String()); err == nil {
		_ = conn.Close()
		t.Fatal("a node with a dialer-proxy must not dial directly")
	}
}

type fakePacketListener struct {
	err   error
	calls int
}

func (f *fakePacketListener) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

// A dialer-proxy that cannot carry UDP must not leave magicsock unable to
// bind after a network change.
func TestTailscalePacketListenerFallsBackToDirect(t *testing.T) {
	failing := &fakePacketListener{err: errors.New("udp not supported")}
	direct := &fakePacketListener{}
	pc, err := listenPacketWithFallback(context.Background(), failing, "group", func() tailscalePacketListener { return direct }, "ts", "udp4", ":0")
	if err != nil {
		t.Fatalf("expected a direct socket, got %v", err)
	}
	_ = pc.Close()
	if direct.calls != 1 {
		t.Fatalf("direct listener calls = %d", direct.calls)
	}

	// Without a dialer-proxy the error stands: there is nothing to fall back to.
	direct.calls = 0
	if _, err := listenPacketWithFallback(context.Background(), failing, "", func() tailscalePacketListener { return direct }, "ts", "udp4", ":0"); err == nil || direct.calls != 0 {
		t.Fatalf("no fallback expected, err=%v calls=%d", err, direct.calls)
	}

	// Both failing reports both.
	if _, err := listenPacketWithFallback(context.Background(), failing, "group", func() tailscalePacketListener { return failing }, "ts", "udp4", ":0"); err == nil {
		t.Fatal("expected an error when both fail")
	}
}

// Through a real dialer-proxy that is missing, magicsock still gets a socket.
func TestTailscaleSystemPacketListenerWithDialerProxy(t *testing.T) {
	node := newTestTailscale(t, TailscaleOption{
		StateDir:    "tailscale/udp",
		BasicOption: BasicOption{DialerProxy: "missing-group"},
	})
	pc, err := node.server.SystemPacketListener(context.Background(), "udp4", ":0")
	if err != nil {
		t.Fatalf("magicsock must get a socket: %v", err)
	}
	_ = pc.Close()
}

func TestTailscaleExitNodeError(t *testing.T) {
	node := &Tailscale{}
	if node.ExitNodeError() != "" {
		t.Fatal("no error before an apply")
	}
	node.setExitNodeErr(errors.New("node 100.64.0.9 is not advertising an exit node"))
	if node.ExitNodeError() == "" {
		t.Fatal("the apply error must be kept")
	}
	node.setExitNodeErr(nil)
	if node.ExitNodeError() != "" {
		t.Fatal("a later success clears it")
	}
}
