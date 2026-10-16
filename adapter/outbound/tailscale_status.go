//go:build with_gvisor && !no_tailscale

// FlClash patch: lets the host read the tsnet node's status and keep one
// node alive across config reloads. Kept in its own file so syncing with
// upstream never conflicts.

package outbound

import (
	"context"
	"errors"
	"fmt"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/tailscale/ipn/ipnstate"
)

var ErrTailscaleNotStarted = errors.New("tailscale node is not started")

// UnwrapTailscale returns the tailscale outbound behind the wrappers the
// parser puts around every adapter.
func UnwrapTailscale(adapter C.ProxyAdapter) (*Tailscale, bool) {
	for adapter != nil {
		switch value := adapter.(type) {
		case *Tailscale:
			return value, true
		case *autoCloseProxyAdapter:
			adapter = value.ProxyAdapter
		default:
			return nil, false
		}
	}
	return nil, false
}

// Started reports whether the node has been brought up by a dial or Start.
func (t *Tailscale) Started() bool {
	return t.serverStarted
}

// Start brings the node up without waiting for traffic to need it.
func (t *Tailscale) Start(ctx context.Context) error {
	return t.ensureStarted(ctx)
}

// Status returns the node's view of the tailnet, including its peers.
func (t *Tailscale) Status(ctx context.Context) (*ipnstate.Status, error) {
	if !t.serverStarted {
		return nil, ErrTailscaleNotStarted
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return nil, err
	}
	return lc.Status(ctx)
}

func tailscaleOptionKey(option TailscaleOption) string {
	acceptRoutes, allowLAN := "", ""
	if option.AcceptRoutes != nil {
		acceptRoutes = fmt.Sprint(*option.AcceptRoutes)
	}
	if option.ExitNodeAllowLANAccess != nil {
		allowLAN = fmt.Sprint(*option.ExitNodeAllowLANAccess)
	}
	return fmt.Sprintf("%q|%q|%q|%q|%q|%v|%v|%s|%q|%s|%v|%v|%q|%d|%v|%q|%q",
		option.Name, option.Hostname, option.AuthKey, option.ControlURL,
		option.StateDir, option.Ephemeral, option.UDP, acceptRoutes,
		option.ExitNode, allowLAN, option.TFO, option.MPTCP, option.Interface,
		option.RoutingMark, option.IPVersion, option.DialerProxy, option.ProviderName)
}

// SameConfig reports whether other was built from the same options, so a
// reload can keep this running node instead of starting a fresh one.
func (t *Tailscale) SameConfig(other *Tailscale) bool {
	return other != nil && tailscaleOptionKey(t.option) == tailscaleOptionKey(other.option)
}

// Adopt makes this node the DNS client for its name again, after the
// replacement built by a reload was dropped in its favour.
func (t *Tailscale) Adopt() {
	t.unregisterDNSResolver = dns.RegisterTailscaleDnsClient(t.option.Name, tailscaleDNSTransport{tailscale: t})
}
