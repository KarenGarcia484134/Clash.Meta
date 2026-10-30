//go:build with_gvisor && !no_tailscale

// FlClash patch: a self-hosted DERP server is usually close to its users,
// often in the same country, and dialing it through the node's
// dialer-proxy sends every relayed packet abroad and back. Dial those
// directly and keep Tailscale's own DERP servers and control on the proxy.
// Kept in its own file so syncing with upstream never conflicts.

package outbound

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/tailcfg"
)

// tailscaleOfficialDERPSuffix is where every DERP server Tailscale runs
// lives. Anything else in the DERP map is the tailnet's own.
const tailscaleOfficialDERPSuffix = ".tailscale.com"

// isCustomDERPNode reports whether n is not one of Tailscale's own servers.
func isCustomDERPNode(n *tailcfg.DERPNode) bool {
	if n == nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n.HostName)), ".")
	return host != "" && !strings.HasSuffix(host, tailscaleOfficialDERPSuffix)
}

// customDERPHosts lists the hostnames and addresses derphttp may dial for
// the self-hosted nodes in m. A region with a self-hosted node counts as
// custom as a whole, since its other nodes are the tailnet's too.
func customDERPHosts(m *tailcfg.DERPMap) map[string]bool {
	hosts := map[string]bool{}
	if m == nil {
		return hosts
	}
	for _, region := range m.Regions {
		if region == nil {
			continue
		}
		custom := false
		for _, n := range region.Nodes {
			if isCustomDERPNode(n) {
				custom = true
				break
			}
		}
		if !custom {
			continue
		}
		for _, n := range region.Nodes {
			if n == nil {
				continue
			}
			for _, host := range []string{n.HostName, n.IPv4, n.IPv6} {
				host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
				if host != "" && host != "none" {
					hosts[host] = true
				}
			}
		}
	}
	return hosts
}

// Route names reported for a DERP region.
const (
	TailscaleRouteDirect = "direct"
	TailscaleRouteProxy  = "proxy"
)

type tailscaleDERPRoutes struct {
	mu     sync.Mutex
	custom map[string]bool
	region map[string]string // host -> region code, for every DERP node
	// route is how each region's DERP connection was last dialed.
	route map[string]string
	// proxied holds the open connections to self-hosted nodes that went
	// through the proxy, to be closed once those nodes may dial directly.
	proxied map[*trackedConn]string
}

func derpRegionHosts(m *tailcfg.DERPMap) map[string]string {
	hosts := map[string]string{}
	if m == nil {
		return hosts
	}
	for id, region := range m.Regions {
		if region == nil {
			continue
		}
		code := region.RegionCode
		if code == "" {
			code = fmt.Sprint(id)
		}
		for _, n := range region.Nodes {
			if n == nil {
				continue
			}
			for _, host := range []string{n.HostName, n.IPv4, n.IPv6} {
				if host = normalizeDERPHost(host); host != "" && host != "none" {
					hosts[host] = code
				}
			}
		}
	}
	return hosts
}

func normalizeDERPHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func derpHostOf(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	return normalizeDERPHost(host)
}

// set takes a new DERP map. The node dials its home DERP as soon as it has
// a map, often one cached from the last run, before the netmap reaches this
// watcher; such a connection to a self-hosted node went through the proxy
// and would stay there. Close it so derphttp redials, now directly.
func (r *tailscaleDERPRoutes) set(m *tailcfg.DERPMap) {
	hosts := customDERPHosts(m)
	regions := derpRegionHosts(m)
	var stale []*trackedConn
	r.mu.Lock()
	r.custom = hosts
	r.region = regions
	for conn, host := range r.proxied {
		if hosts[host] {
			stale = append(stale, conn)
			delete(r.proxied, conn)
		}
	}
	r.mu.Unlock()
	for _, conn := range stale {
		_ = conn.Conn.Close()
	}
}

// direct reports whether address belongs to a self-hosted DERP node.
func (r *tailscaleDERPRoutes) direct(address string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.custom[derpHostOf(address)]
}

func (r *tailscaleDERPRoutes) record(address, route string, conn net.Conn) net.Conn {
	host := derpHostOf(address)
	r.mu.Lock()
	defer r.mu.Unlock()
	if code, ok := r.region[host]; ok {
		if r.route == nil {
			r.route = map[string]string{}
		}
		r.route[code] = route
	}
	if route != TailscaleRouteProxy || conn == nil {
		return conn
	}
	tracked := &trackedConn{Conn: conn, routes: r}
	if r.proxied == nil {
		r.proxied = map[*trackedConn]string{}
	}
	r.proxied[tracked] = host
	return tracked
}

// Routes returns how each DERP region was last dialed, by region code.
func (r *tailscaleDERPRoutes) Routes() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.route))
	for code, route := range r.route {
		out[code] = route
	}
	return out
}

type trackedConn struct {
	net.Conn
	routes *tailscaleDERPRoutes
}

func (c *trackedConn) Close() error {
	c.routes.mu.Lock()
	delete(c.routes.proxied, c)
	c.routes.mu.Unlock()
	return c.Conn.Close()
}

type tailscaleStreamDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// dialSystemVia dials a self-hosted DERP node directly, falling back to the
// proxy when the direct dial fails, and everything else through primary.
func dialSystemVia(ctx context.Context, routes *tailscaleDERPRoutes, primary tailscaleStreamDialer, via string, direct func() tailscaleStreamDialer, name, network, address string) (net.Conn, error) {
	if routes == nil {
		return primary.DialContext(ctx, network, address)
	}
	if via == "" {
		conn, err := primary.DialContext(ctx, network, address)
		if err == nil {
			conn = routes.record(address, TailscaleRouteDirect, conn)
		}
		return conn, err
	}
	if routes.direct(address) {
		conn, err := direct().DialContext(ctx, network, address)
		if err == nil {
			log.Infoln("[Tailscale](%s) self-hosted DERP %s dialed directly", name, address)
			return routes.record(address, TailscaleRouteDirect, conn), nil
		}
		log.Infoln("[Tailscale](%s) direct dial to self-hosted DERP %s failed (%v), using %s", name, address, err, via)
		conn, err = primary.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		// Not tracked: it went through the proxy because direct failed.
		routes.record(address, TailscaleRouteProxy, nil)
		return conn, nil
	}
	conn, err := primary.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return routes.record(address, TailscaleRouteProxy, conn), nil
}

// DERPRoutes reports, by region code, whether the node's DERP connection to
// each region it dialed went directly or through the proxy.
func (t *Tailscale) DERPRoutes() map[string]string {
	return t.derpRoutes.Routes()
}

// dialSystem is the node's SystemDialer. The direct dialer is mihomo's own,
// which on Android protects the socket and binds it to the underlying
// network, so it never loops back through FlClash's tun.
func (t *Tailscale) dialSystem(ctx context.Context, network, address string) (net.Conn, error) {
	return dialSystemVia(ctx, &t.derpRoutes, t.dialer, t.option.DialerProxy, func() tailscaleStreamDialer {
		return dialer.NewDialer(t.DialOptions()...)
	}, t.Name(), network, address)
}

// watchDERPMap keeps the set of self-hosted DERP nodes in step with the
// DERP map the control server sends.
func (t *Tailscale) watchDERPMap() {
	lc, err := t.server.LocalClient()
	if err != nil {
		return
	}
	watcher, err := lc.WatchIPNBus(t.ctx, ipn.NotifyInitialNetMap)
	if err != nil {
		return
	}
	defer watcher.Close()
	for {
		n, err := watcher.Next()
		if err != nil {
			return
		}
		if n.NetMap != nil {
			t.derpRoutes.set(n.NetMap.DERPMap)
		}
	}
}
