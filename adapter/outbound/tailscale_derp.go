//go:build with_gvisor && !no_tailscale

// FlClash patch: a self-hosted DERP server is usually close to its users,
// often in the same country, and dialing it through the node's
// dialer-proxy sends every relayed packet abroad and back. Dial those
// directly and keep Tailscale's own DERP servers and control on the proxy.
// Kept in its own file so syncing with upstream never conflicts.

package outbound

import (
	"context"
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

type tailscaleDERPRoutes struct {
	mu     sync.RWMutex
	custom map[string]bool
}

func (r *tailscaleDERPRoutes) set(m *tailcfg.DERPMap) {
	hosts := customDERPHosts(m)
	r.mu.Lock()
	r.custom = hosts
	r.mu.Unlock()
}

// direct reports whether address belongs to a self-hosted DERP node.
func (r *tailscaleDERPRoutes) direct(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.custom[host]
}

type tailscaleStreamDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// dialSystemVia dials a self-hosted DERP node directly, falling back to the
// proxy when the direct dial fails, and everything else through primary.
func dialSystemVia(ctx context.Context, routes *tailscaleDERPRoutes, primary tailscaleStreamDialer, via string, direct func() tailscaleStreamDialer, name, network, address string) (net.Conn, error) {
	if via == "" || routes == nil || !routes.direct(address) {
		return primary.DialContext(ctx, network, address)
	}
	conn, err := direct().DialContext(ctx, network, address)
	if err == nil {
		log.Debugln("[Tailscale](%s) self-hosted DERP %s dialed directly", name, address)
		return conn, nil
	}
	log.Infoln("[Tailscale](%s) direct dial to self-hosted DERP %s failed (%v), using %s", name, address, err, via)
	return primary.DialContext(ctx, network, address)
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
	if t.option.DialerProxy == "" {
		return
	}
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
