//go:build with_gvisor && !no_tailscale

// FlClash patch: the dialer-proxy exists so the node can reach the control
// server, but magicsock binds UDP directly and so picks the DERP region
// closest to the device; relaying that region's traffic through the proxy
// sends every packet abroad and back. Dial every DERP node, Tailscale's own
// included, directly first, and keep control on the proxy.
// Kept in its own file so syncing with upstream never conflicts.

package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/tailcfg"
)

// Route names reported for a DERP region.
const (
	TailscaleRouteDirect = "direct"
	TailscaleRouteProxy  = "proxy"
)

// derpNodeHost is what is known about one host or address derphttp may dial.
type derpNodeHost struct {
	region     string
	serverName string
	// hasIPv4 means derphttp races a tcp4 dial for the same node, which
	// makes a failed tcp6 one safe to drop instead of proxying.
	hasIPv4 bool
}

// derpDirectHealth backs a direct path off after it fails. A TCP connect is
// not proof enough: a filter that matches the TLS SNI lets the connect
// through and resets the handshake, and each redial would hit it again.
type derpDirectHealth struct {
	failures int
	until    time.Time
}

type tailscaleDERPRoutes struct {
	mu    sync.Mutex
	hosts map[string]derpNodeHost
	// route is how each region's DERP connection was last dialed.
	route map[string]string
	// proxied holds the open proxied connections to hosts not yet known
	// as DERP nodes, to be closed once the map shows they are.
	proxied map[*trackedConn]string
	// fallback holds the DERP connections that went through the proxy
	// because the direct path failed; each is re-probed and closed once a
	// direct handshake works again, so derphttp redials directly.
	fallback map[*trackedConn]string
	health   map[string]*derpDirectHealth
	closed   bool
	probeCtx context.Context
	cancel   context.CancelFunc
}

var (
	// derpDirectRetryInterval is how often a DERP connection that fell back
	// to the proxy re-checks whether the direct path works again.
	derpDirectRetryInterval = 30 * time.Second
	derpDirectBackoffBase   = time.Minute
	derpDirectBackoffMax    = 15 * time.Minute
	// A direct connection that has read something and is still open this
	// long clears its path's backoff. One that wrote and ends without
	// reading a byte failed: that is how a reset handshake looks.
	derpDirectHealthyAfter = 10 * time.Second
	derpDirectProbe        = probeDERPHandshake
)

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

func derpNodeHosts(m *tailcfg.DERPMap) map[string]derpNodeHost {
	hosts := map[string]derpNodeHost{}
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
			if n == nil || n.STUNOnly {
				continue
			}
			v4 := strings.TrimSpace(n.IPv4)
			info := derpNodeHost{
				region:     code,
				serverName: strings.TrimSuffix(strings.TrimSpace(n.HostName), "."),
				hasIPv4:    v4 == "" || isIPv4Literal(v4),
			}
			for _, host := range []string{n.HostName, n.IPv4, n.IPv6} {
				if host = normalizeDERPHost(host); host != "" && host != "none" {
					hosts[host] = info
				}
			}
		}
	}
	return hosts
}

func isIPv4Literal(s string) bool {
	ip, err := netip.ParseAddr(s)
	return err == nil && ip.Is4()
}

// set takes a new DERP map. The node dials its home DERP as soon as it has
// a map, often one cached from the last run, before the netmap reaches this
// watcher; such a connection went through the proxy and would stay there.
// Close it so derphttp redials, now directly.
func (r *tailscaleDERPRoutes) set(m *tailcfg.DERPMap) {
	hosts := derpNodeHosts(m)
	var stale []*trackedConn
	r.mu.Lock()
	r.hosts = hosts
	for conn, host := range r.proxied {
		if _, ok := hosts[host]; ok {
			stale = append(stale, conn)
			delete(r.proxied, conn)
		}
	}
	r.mu.Unlock()
	for _, conn := range stale {
		_ = conn.Close()
	}
}

func (r *tailscaleDERPRoutes) closeAll() {
	r.mu.Lock()
	r.closed = true
	if r.cancel != nil {
		r.cancel()
	}
	conns := make([]*trackedConn, 0, len(r.proxied)+len(r.fallback))
	for conn := range r.proxied {
		conns = append(conns, conn)
	}
	r.proxied = nil
	for conn := range r.fallback {
		conns = append(conns, conn)
	}
	r.fallback = nil
	r.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (r *tailscaleDERPRoutes) node(address string) (derpNodeHost, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	info, ok := r.hosts[derpHostOf(address)]
	return info, ok
}

func derpHealthKey(network, address string) string {
	return network + "|" + derpHostOf(address)
}

// directAllowed reports whether the direct path to address is out of its
// backoff.
func (r *tailscaleDERPRoutes) directAllowed(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.health[key]
	return h == nil || !time.Now().Before(h.until)
}

func (r *tailscaleDERPRoutes) directFailed(key string) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.health == nil {
		r.health = map[string]*derpDirectHealth{}
	}
	h := r.health[key]
	if h == nil {
		h = &derpDirectHealth{}
		r.health[key] = h
	}
	backoff := derpDirectBackoffBase
	for i := 0; i < h.failures && backoff < derpDirectBackoffMax; i++ {
		backoff *= 2
	}
	if backoff > derpDirectBackoffMax {
		backoff = derpDirectBackoffMax
	}
	h.failures++
	h.until = time.Now().Add(backoff)
	return backoff
}

func (r *tailscaleDERPRoutes) directHealthy(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.health, key)
}

// resetHealth forgets every failed direct path, which says nothing about
// the network the device has just joined.
func (r *tailscaleDERPRoutes) resetHealth() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.health = nil
}

func (r *tailscaleDERPRoutes) recordRoute(region, route string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.route == nil {
		r.route = map[string]string{}
	}
	r.route[region] = route
}

// trackProxied records a proxied connection to a host not known as a DERP
// node, which set closes if the map later shows it is one. If a concurrent map
// update already marked the host as a DERP node, it reports becameDERP=true.
func (r *tailscaleDERPRoutes) trackProxied(address string, conn net.Conn) (net.Conn, derpNodeHost, bool) {
	host := derpHostOf(address)
	r.mu.Lock()
	if info, isDERP := r.hosts[host]; isDERP {
		r.mu.Unlock()
		return nil, info, true
	}
	tracked := newTrackedConn(conn, r)
	if !r.closed {
		if r.proxied == nil {
			r.proxied = map[*trackedConn]string{}
		}
		r.proxied[tracked] = host
	}
	r.mu.Unlock()
	return tracked, derpNodeHost{}, false
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
	once   sync.Once
	closed chan struct{}
}

func newTrackedConn(conn net.Conn, routes *tailscaleDERPRoutes) *trackedConn {
	return &trackedConn{
		Conn:   conn,
		routes: routes,
		closed: make(chan struct{}),
	}
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	c.routes.mu.Lock()
	delete(c.routes.proxied, c)
	delete(c.routes.fallback, c)
	c.routes.mu.Unlock()
	return c.Conn.Close()
}

// directDERPConn judges a direct DERP connection by how it ends. derphttp
// closes the connection when the TLS handshake or the upgrade fails, and a
// loser of its IPv4/IPv6 race is closed before anything was written.
type directDERPConn struct {
	net.Conn
	routes  *tailscaleDERPRoutes
	key     string
	address string
	opened  time.Time
	wrote   atomic.Bool
	read    atomic.Bool
	once    sync.Once
	healthy *time.Timer
}

func (r *tailscaleDERPRoutes) watchDirect(conn net.Conn, key, address string) net.Conn {
	c := &directDERPConn{Conn: conn, routes: r, key: key, address: address, opened: time.Now()}
	c.healthy = time.AfterFunc(derpDirectHealthyAfter, func() {
		if c.read.Load() {
			r.directHealthy(key)
		}
	})
	return c
}

func (c *directDERPConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.read.Store(true)
	}
	return n, err
}

func (c *directDERPConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.wrote.Store(true)
	}
	return n, err
}

func (c *directDERPConn) Close() error {
	c.once.Do(func() {
		c.healthy.Stop()
		if !c.wrote.Load() {
			return
		}
		if c.read.Load() {
			if time.Since(c.opened) >= derpDirectHealthyAfter {
				c.routes.directHealthy(c.key)
			}
			return
		}
		backoff := c.routes.directFailed(c.key)
		log.Infoln("[Tailscale] direct DERP connection to %s ended early, using the proxy for %v", c.address, backoff)
	})
	return c.Conn.Close()
}

// probeDERPHandshake checks that a TLS handshake to the node completes,
// which a TCP connect alone does not show. The certificate is derphttp's to
// verify; the probe only asks whether the path carries the handshake.
func probeDERPHandshake(ctx context.Context, conn net.Conn, serverName string) error {
	if serverName == "" {
		return nil
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	return tlsConn.HandshakeContext(ctx)
}

// trackFallback records a proxied DERP connection and re-probes the direct
// path once its backoff is over. Once a direct handshake succeeds the
// proxied connection is closed so derphttp redials, now directly.
func (r *tailscaleDERPRoutes) trackFallback(conn net.Conn, network, address, key, serverName string, direct func() tailscaleStreamDialer) net.Conn {
	tracked := newTrackedConn(conn, r)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return tracked
	}
	if r.fallback == nil {
		r.fallback = map[*trackedConn]string{}
	}
	r.fallback[tracked] = address
	if r.probeCtx == nil {
		r.probeCtx, r.cancel = context.WithCancel(context.Background())
	}
	baseCtx := r.probeCtx
	r.mu.Unlock()
	interval := derpDirectRetryInterval
	go func() {
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
			case <-tracked.closed:
				return
			case <-baseCtx.Done():
				return
			}
			r.mu.Lock()
			_, alive := r.fallback[tracked]
			r.mu.Unlock()
			if !alive {
				return
			}
			if !r.directAllowed(key) {
				timer.Reset(interval)
				continue
			}
			ctx, cancel := context.WithTimeout(baseCtx, 5*time.Second)
			probe, err := direct().DialContext(ctx, network, address)
			if err == nil {
				err = derpDirectProbe(ctx, probe, serverName)
				_ = probe.Close()
			}
			cancel()
			if baseCtx.Err() != nil {
				return
			}
			if err != nil {
				r.directFailed(key)
				timer.Reset(interval)
				continue
			}
			log.Infoln("[Tailscale] DERP %s reachable directly again, redialing off the proxy", address)
			_ = tracked.Close()
			return
		}
	}()
	return tracked
}

type tailscaleStreamDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// dialSystemVia dials a DERP node directly, falling back to the proxy when
// the direct path fails, and everything else through primary.
func dialSystemVia(ctx context.Context, routes *tailscaleDERPRoutes, primary tailscaleStreamDialer, via string, direct func() tailscaleStreamDialer, name, network, address string) (net.Conn, error) {
	if routes == nil {
		return primary.DialContext(ctx, network, address)
	}
	node, isDERP := routes.node(address)
	if via == "" {
		conn, err := primary.DialContext(ctx, network, address)
		if err == nil && isDERP {
			routes.recordRoute(node.region, TailscaleRouteDirect)
		}
		return conn, err
	}
	if !isDERP {
		conn, err := primary.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		tracked, derpNode, becameDERP := routes.trackProxied(address, conn)
		if !becameDERP {
			return tracked, nil
		}
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		node = derpNode
	}

	key := derpHealthKey(network, address)
	var directErr error
	if routes.directAllowed(key) {
		// derphttp gives each node only a short deadline; leave half of
		// it for the proxy fallback instead of letting a hanging direct
		// dial eat all of it.
		directCtx := ctx
		if deadline, ok := ctx.Deadline(); ok {
			var cancel context.CancelFunc
			directCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)/2)
			defer cancel()
		}
		conn, err := direct().DialContext(directCtx, network, address)
		if err == nil {
			log.Debugln("[Tailscale](%s) DERP %s dialed directly", name, address)
			routes.recordRoute(node.region, TailscaleRouteDirect)
			return routes.watchDirect(conn, key, address), nil
		}
		// The losing dial of derphttp's race is cancelled, which is not
		// the path's fault.
		if ctx.Err() != nil {
			return nil, err
		}
		directErr = err
		backoff := routes.directFailed(key)
		log.Infoln("[Tailscale](%s) direct dial to DERP %s failed (%v), using %s for %v", name, address, err, via, backoff)
	}
	// The tcp4 dial derphttp races beside this one takes the proxy if it
	// must; two proxied dials would only race each other.
	if network == "tcp6" && node.hasIPv4 {
		if directErr == nil {
			directErr = fmt.Errorf("direct IPv6 path to %s is backing off", address)
		}
		return nil, directErr
	}
	conn, err := primary.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	routes.recordRoute(node.region, TailscaleRouteProxy)
	return routes.trackFallback(conn, network, address, key, node.serverName, direct), nil
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

// watchDERPMap keeps the set of DERP nodes in step with the DERP map the
// control server sends. Outside Windows the IPN bus carries a NetMap only in
// the first message, sent before the node has logged in, so the DERP map is
// read back through the LocalAPI on every later message.
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
	var last *tailcfg.DERPMap
	for {
		n, err := watcher.Next()
		if err != nil {
			return
		}
		m := (*tailcfg.DERPMap)(nil)
		if n.NetMap != nil {
			m = n.NetMap.DERPMap
		}
		if m == nil {
			ctx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
			m, _ = lc.CurrentDERPMap(ctx)
			cancel()
		}
		if m == nil || reflect.DeepEqual(m, last) {
			continue
		}
		last = m
		t.derpRoutes.set(m)
	}
}
