//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/tailscale/tailcfg"
)

func testDERPMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		4: {RegionID: 4, RegionCode: "fra", Nodes: []*tailcfg.DERPNode{
			{Name: "4f", HostName: "derp4f.tailscale.com", IPv4: "1.1.1.4"},
		}},
		900: {RegionID: 900, RegionCode: "tx-cd-derp", Nodes: []*tailcfg.DERPNode{
			{Name: "900a", HostName: "derp.example.cn", IPv4: "203.0.113.7", IPv6: "2001:db8::7"},
			{Name: "900b", HostName: "VM-0-7-debian.", IPv4: "none"},
		}},
	}}
}

func TestDERPNodeHosts(t *testing.T) {
	hosts := derpNodeHosts(testDERPMap())
	for _, host := range []string{"derp.example.cn", "203.0.113.7", "2001:db8::7", "vm-0-7-debian", "derp4f.tailscale.com", "1.1.1.4"} {
		if _, ok := hosts[host]; !ok {
			t.Errorf("%s must count as a DERP node", host)
		}
	}
	for _, host := range []string{"controlplane.tailscale.com", "none"} {
		if _, ok := hosts[host]; ok {
			t.Errorf("%s is not a DERP node", host)
		}
	}
	if got := hosts["1.1.1.4"]; got.region != "fra" || got.serverName != "derp4f.tailscale.com" || !got.hasIPv4 {
		t.Errorf("1.1.1.4 = %+v", got)
	}
	if hosts["vm-0-7-debian"].hasIPv4 {
		t.Error("a node with IPv4 none races no tcp4 dial")
	}
	if len(derpNodeHosts(nil)) != 0 {
		t.Fatal("no map, no hosts")
	}
}

type fakeStreamDialer struct {
	err   error
	calls []string
}

func (f *fakeStreamDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	f.calls = append(f.calls, address)
	if f.err != nil {
		return nil, f.err
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func TestDialSystemRoutesSelfHostedDERPDirectly(t *testing.T) {
	var routes tailscaleDERPRoutes
	routes.set(testDERPMap())
	proxy, direct := &fakeStreamDialer{}, &fakeStreamDialer{}
	directOf := func() tailscaleStreamDialer { return direct }
	dial := func(via, address string) {
		t.Helper()
		conn, err := dialSystemVia(context.Background(), &routes, proxy, via, directOf, "ts", "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}

	dial("group", "203.0.113.7:443")
	dial("group", "[2001:db8::7]:443")
	dial("group", "derp.example.cn:443")
	if len(direct.calls) != 3 || len(proxy.calls) != 0 {
		t.Fatalf("self-hosted DERP must dial directly: direct=%v proxy=%v", direct.calls, proxy.calls)
	}

	direct.calls = nil
	dial("group", "1.1.1.4:443")
	dial("group", "controlplane.tailscale.com:443")
	if len(direct.calls) != 1 || direct.calls[0] != "1.1.1.4:443" || len(proxy.calls) != 1 {
		t.Fatalf("official DERP dials directly, control stays on the proxy: direct=%v proxy=%v", direct.calls, proxy.calls)
	}

	// A failed direct dial falls back to the proxy.
	proxy.calls, direct.calls = nil, nil
	direct.err = errors.New("blocked")
	dial("group", "203.0.113.7:443")
	if len(direct.calls) != 1 || len(proxy.calls) != 1 {
		t.Fatalf("fallback expected: direct=%v proxy=%v", direct.calls, proxy.calls)
	}

	// Without a dialer-proxy everything goes the one way it already does.
	proxy.calls, direct.calls = nil, nil
	dial("", "203.0.113.7:443")
	if len(direct.calls) != 0 || len(proxy.calls) != 1 {
		t.Fatalf("no dialer-proxy uses the node's dialer: direct=%v proxy=%v", direct.calls, proxy.calls)
	}

	// A map that drops the region drops its route.
	routes.set(&tailcfg.DERPMap{})
	routes.resetHealth()
	proxy.calls, direct.calls = nil, nil
	direct.err = nil
	dial("group", "203.0.113.7:443")
	if len(direct.calls) != 0 {
		t.Fatal("a region no longer in the map must use the proxy")
	}
}

type closeCounter struct {
	net.Conn
	closed *int
}

func (c closeCounter) Close() error { *c.closed++; return c.Conn.Close() }

type countingDialer struct{ closed int }

func (d *countingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	_ = b.Close()
	return closeCounter{Conn: a, closed: &d.closed}, nil
}

// The home DERP is dialed from the cached map before the netmap arrives;
// once the map shows the host is a DERP node that proxied connection is
// closed so derphttp redials it directly, and the route is reported.
func TestDERPConnDialedBeforeTheMapIsRedialedDirectly(t *testing.T) {
	var routes tailscaleDERPRoutes
	proxy := &countingDialer{}
	direct := &fakeStreamDialer{}
	directOf := func() tailscaleStreamDialer { return direct }

	early, err := dialSystemVia(context.Background(), &routes, proxy, "group", directOf, "ts", "tcp", "203.0.113.7:443")
	if err != nil {
		t.Fatal(err)
	}
	control, err := dialSystemVia(context.Background(), &routes, proxy, "group", directOf, "ts", "tcp", "controlplane.tailscale.com:443")
	if err != nil {
		t.Fatal(err)
	}
	routes.set(testDERPMap())
	if proxy.closed != 1 {
		t.Fatalf("only the proxied DERP conn must be closed, got %d closes", proxy.closed)
	}
	_ = early.Close()
	_ = control.Close()

	conn, err := dialSystemVia(context.Background(), &routes, proxy, "group", directOf, "ts", "tcp", "203.0.113.7:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(direct.calls) != 1 {
		t.Fatalf("redial must be direct: %v", direct.calls)
	}
	direct.err = errors.New("blocked")
	conn, err = dialSystemVia(context.Background(), &routes, proxy, "group", directOf, "ts", "tcp", "1.1.1.4:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	got := routes.Routes()
	if got["tx-cd-derp"] != TailscaleRouteDirect || got["fra"] != TailscaleRouteProxy {
		t.Fatalf("routes = %v", got)
	}
}

type toggleStreamDialer struct {
	mu   sync.Mutex
	fail bool
}

func (f *toggleStreamDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, errors.New("direct down")
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func fastDERPRetries(t *testing.T) {
	t.Helper()
	interval, base, probe := derpDirectRetryInterval, derpDirectBackoffBase, derpDirectProbe
	derpDirectRetryInterval = 20 * time.Millisecond
	derpDirectBackoffBase = 10 * time.Millisecond
	derpDirectProbe = func(context.Context, net.Conn, string) error { return nil }
	t.Cleanup(func() {
		derpDirectRetryInterval, derpDirectBackoffBase, derpDirectProbe = interval, base, probe
	})
}

// A DERP connection that fell back to the proxy must not stay there once
// the direct path works again.
func TestDialSystemFallbackReturnsToDirect(t *testing.T) {
	fastDERPRetries(t)

	var routes tailscaleDERPRoutes
	routes.set(testDERPMap())
	direct := &toggleStreamDialer{fail: true}
	proxyA, proxyB := net.Pipe()
	defer proxyB.Close()
	proxy := streamDialerFunc(func() (net.Conn, error) { return proxyA, nil })
	conn, err := dialSystemVia(context.Background(), &routes, proxy, "group",
		func() tailscaleStreamDialer { return direct }, "ts", "tcp", "203.0.113.7:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	direct.mu.Lock()
	direct.fail = false
	direct.mu.Unlock()

	done := make(chan struct{})
	go func() { _, _ = proxyB.Read(make([]byte, 1)); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxied fallback connection to self-hosted DERP was never closed after direct recovered")
	}
}

type streamDialerFunc func() (net.Conn, error)

func (f streamDialerFunc) DialContext(context.Context, string, string) (net.Conn, error) { return f() }

// The filter that matters resets the TLS handshake after the TCP connect
// went through: the direct connection writes its ClientHello, reads
// nothing and is closed. The next dial must take the proxy rather than
// hitting the same reset, and a probe that cannot finish a handshake must
// not send it back.
func TestDirectDERPResetDuringHandshakeBacksOff(t *testing.T) {
	var routes tailscaleDERPRoutes
	routes.set(testDERPMap())
	proxy := &fakeStreamDialer{}
	var directCalls []string
	direct := streamDialerFunc(func() (net.Conn, error) {
		directCalls = append(directCalls, "dial")
		a, b := net.Pipe()
		go func() { _, _ = b.Read(make([]byte, 64)); _ = b.Close() }()
		return a, nil
	})
	directOf := func() tailscaleStreamDialer { return direct }

	conn, err := dialSystemVia(context.Background(), &routes, proxy, "group", directOf, "ts", "tcp4", "1.1.1.4:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("client hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the reset handshake must read nothing")
	}
	_ = conn.Close()

	conn, err = dialSystemVia(context.Background(), &routes, proxy, "group", directOf, "ts", "tcp4", "1.1.1.4:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if len(directCalls) != 1 || len(proxy.calls) != 1 {
		t.Fatalf("a reset direct path must back off to the proxy: direct=%d proxy=%v", len(directCalls), proxy.calls)
	}
	if got := routes.Routes()["fra"]; got != TailscaleRouteProxy {
		t.Fatalf("route = %q", got)
	}

	routes.resetHealth()
	if !routes.directAllowed(derpHealthKey("tcp4", "1.1.1.4:443")) {
		t.Fatal("a network change must let the direct path be tried again")
	}
}

// A connection that read its peer's answer is healthy whatever closes it,
// and the loser of derphttp's IPv4/IPv6 race is closed before writing.
func TestDirectDERPHealthyOrUnusedConnKeepsDirect(t *testing.T) {
	var routes tailscaleDERPRoutes
	routes.set(testDERPMap())
	direct := streamDialerFunc(func() (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			buf := make([]byte, 64)
			for {
				n, err := b.Read(buf)
				if err != nil {
					return
				}
				_, _ = b.Write(buf[:n])
			}
		}()
		return a, nil
	})
	directOf := func() tailscaleStreamDialer { return direct }
	key := derpHealthKey("tcp4", "1.1.1.4:443")

	unused, err := dialSystemVia(context.Background(), &routes, &fakeStreamDialer{}, "group", directOf, "ts", "tcp4", "1.1.1.4:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = unused.Close()

	answered, err := dialSystemVia(context.Background(), &routes, &fakeStreamDialer{}, "group", directOf, "ts", "tcp4", "1.1.1.4:443")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = answered.Write([]byte("hi"))
	_, _ = answered.Read(make([]byte, 2))
	_ = answered.Close()

	if !routes.directAllowed(key) {
		t.Fatal("neither an unused nor an answered connection may back the direct path off")
	}
}

// derphttp races tcp4 and tcp6 for one node. Without IPv6 the tcp6 dial
// fails at once, and proxying it would only race the direct tcp4 dial.
func TestFailedIPv6DERPDialIsNotProxiedBesideIPv4(t *testing.T) {
	var routes tailscaleDERPRoutes
	routes.set(testDERPMap())
	proxy := &fakeStreamDialer{}
	direct := &fakeStreamDialer{err: errors.New("network is unreachable")}
	directOf := func() tailscaleStreamDialer { return direct }

	if _, err := dialSystemVia(context.Background(), &routes, proxy, "group", directOf, "ts", "tcp6", "[2001:db8::7]:443"); err == nil {
		t.Fatal("a failed tcp6 dial of a node with IPv4 must fail")
	}
	if _, err := dialSystemVia(context.Background(), &routes, proxy, "group", directOf, "ts", "tcp6", "[2001:db8::7]:443"); err == nil {
		t.Fatal("a backed-off tcp6 dial must fail too")
	}
	if len(direct.calls) != 1 || len(proxy.calls) != 0 {
		t.Fatalf("direct=%v proxy=%v", direct.calls, proxy.calls)
	}

	conn, err := dialSystemVia(context.Background(), &routes, proxy, "group", directOf, "ts", "tcp4", "203.0.113.7:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(proxy.calls) != 1 {
		t.Fatalf("the tcp4 dial takes the proxy when direct fails: %v", proxy.calls)
	}
}

type blockingStreamDialer struct{}

func (blockingStreamDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// The losing dial of a race is cancelled; that says nothing about the path.
func TestCancelledDirectDERPDialKeepsDirect(t *testing.T) {
	var routes tailscaleDERPRoutes
	routes.set(testDERPMap())
	proxy := &fakeStreamDialer{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dialSystemVia(ctx, &routes, proxy, "group", func() tailscaleStreamDialer { return blockingStreamDialer{} }, "ts", "tcp4", "1.1.1.4:443")
	if err == nil {
		t.Fatal("a cancelled dial must fail")
	}
	if len(proxy.calls) != 0 || !routes.directAllowed(derpHealthKey("tcp4", "1.1.1.4:443")) {
		t.Fatalf("a cancelled dial must neither proxy nor back off: proxy=%v", proxy.calls)
	}
}

// A probe through a path that resets the handshake must keep the proxied
// connection, and back the path off further.
func TestFallbackProbeNeedsAHandshake(t *testing.T) {
	fastDERPRetries(t)
	var probes atomic.Int32
	derpDirectProbe = func(context.Context, net.Conn, string) error {
		probes.Add(1)
		return errors.New("connection reset by peer")
	}

	var routes tailscaleDERPRoutes
	routes.set(testDERPMap())
	direct := &toggleStreamDialer{fail: true}
	proxyA, proxyB := net.Pipe()
	defer proxyB.Close()
	proxy := streamDialerFunc(func() (net.Conn, error) { return proxyA, nil })
	conn, err := dialSystemVia(context.Background(), &routes, proxy, "group",
		func() tailscaleStreamDialer { return direct }, "ts", "tcp4", "1.1.1.4:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	direct.mu.Lock()
	direct.fail = false
	direct.mu.Unlock()

	done := make(chan struct{})
	go func() { _, _ = proxyB.Read(make([]byte, 1)); close(done) }()
	select {
	case <-done:
		t.Fatal("the proxied connection was closed though no direct handshake worked")
	case <-time.After(300 * time.Millisecond):
	}
	if probes.Load() == 0 {
		t.Fatal("the direct path was never probed")
	}
	routes.mu.Lock()
	failures := routes.health[derpHealthKey("tcp4", "1.1.1.4:443")].failures
	routes.mu.Unlock()
	if failures < 2 {
		t.Fatalf("a failed probe must back the path off further, failures=%d", failures)
	}
}
