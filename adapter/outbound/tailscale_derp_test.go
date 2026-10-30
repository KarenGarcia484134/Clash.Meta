//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net"
	"testing"

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

func TestCustomDERPHosts(t *testing.T) {
	hosts := customDERPHosts(testDERPMap())
	for _, host := range []string{"derp.example.cn", "203.0.113.7", "2001:db8::7", "vm-0-7-debian"} {
		if !hosts[host] {
			t.Errorf("%s must count as self-hosted", host)
		}
	}
	for _, host := range []string{"derp4f.tailscale.com", "1.1.1.4", "none"} {
		if hosts[host] {
			t.Errorf("%s must stay on the proxy", host)
		}
	}
	if len(customDERPHosts(nil)) != 0 {
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
	if len(direct.calls) != 0 || len(proxy.calls) != 2 {
		t.Fatalf("official DERP and control stay on the proxy: direct=%v proxy=%v", direct.calls, proxy.calls)
	}

	// A failed direct dial falls back to the proxy.
	proxy.calls = nil
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
	proxy.calls, direct.calls = nil, nil
	direct.err = nil
	dial("group", "203.0.113.7:443")
	if len(direct.calls) != 0 {
		t.Fatal("a region no longer in the map must use the proxy")
	}
}
