//go:build with_gvisor && !no_tailscale

// FlClash patch: lets the host read the tsnet node's status and keep one
// node alive across config reloads. Kept in its own file so syncing with
// upstream never conflicts.

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/tailcfg"
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

// TailscaleSettled reports whether the node stays in state without more work
// of its own. A fresh node passes through NeedsLogin before the control
// client has logged in with its saved key, so NeedsLogin only counts once
// there is a login URL to show.
func TailscaleSettled(state, authURL string) bool {
	switch state {
	case ipn.Running.String(), ipn.NeedsMachineAuth.String(), ipn.Stopped.String():
		return true
	case ipn.NeedsLogin.String():
		return authURL != ""
	}
	return false
}

// WaitSettled follows the IPN bus until the node settles or ctx ends, and
// returns the last state and login URL it saw.
func (t *Tailscale) WaitSettled(ctx context.Context) (state, authURL string, err error) {
	if !t.serverStarted {
		return "", "", ErrTailscaleNotStarted
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return "", "", err
	}
	watcher, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialState)
	if err != nil {
		return "", "", err
	}
	defer watcher.Close()
	for {
		n, err := watcher.Next()
		if err != nil {
			if ctx.Err() != nil {
				return state, authURL, nil
			}
			return state, authURL, err
		}
		if n.State != nil {
			state = n.State.String()
		}
		if n.BrowseToURL != nil {
			authURL = *n.BrowseToURL
		}
		if TailscaleSettled(state, authURL) {
			return state, authURL, nil
		}
	}
}

// NetworkChanged makes the node re-check the network now. On Android tsnet
// only polls for link changes every ten minutes and counts on the host app to
// report them, so without this a switch between Wi-Fi and mobile data leaves
// the node on dead sockets for minutes. The check closes the connections the
// switch broke, rebinds magicsock and reconnects DERP and control; the node
// and its login stay as they are.
func (t *Tailscale) NetworkChanged() {
	if !t.serverStarted || t.server == nil {
		return
	}
	sys := t.server.Sys()
	if sys == nil {
		return
	}
	if monitor, ok := sys.NetMon.GetOK(); ok && monitor != nil {
		monitor.InjectEvent()
	}
}

// Ping sends one ping of pingType to ip through the node. A disco ping also
// tells whether the path is direct or through a relay.
func (t *Tailscale) Ping(ctx context.Context, ip netip.Addr, pingType tailcfg.PingType) (*ipnstate.PingResult, error) {
	if !t.serverStarted {
		return nil, ErrTailscaleNotStarted
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return nil, err
	}
	return lc.Ping(ctx, ip, pingType)
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

// DialerProxy names the proxy or group the node's own control, DERP and UDP
// traffic goes through; empty means it dials directly.
func (t *Tailscale) DialerProxy() string {
	return t.option.DialerProxy
}

// TailscaleNeedsReconnect reports whether a started node is stuck without
// getting anywhere on its own: logged out with no login URL to show, which
// is where a failed control dial leaves a node that has a saved key.
func TailscaleNeedsReconnect(state, authURL string) bool {
	switch state {
	case ipn.NeedsLogin.String():
		return authURL == ""
	case ipn.NoState.String(), ipn.Starting.String():
		return true
	}
	return false
}

// Reconnect makes a stuck node log in again now instead of waiting out the
// control client's backoff, as tailscale down and up would. The saved login
// stays, so a node that was logged in comes back without a new login URL.
func (t *Tailscale) Reconnect(ctx context.Context) error {
	if !t.serverStarted {
		return ErrTailscaleNotStarted
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		return err
	}
	if !TailscaleNeedsReconnect(status.BackendState, status.AuthURL) {
		return nil
	}
	for _, want := range []bool{false, true} {
		if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs:          ipn.Prefs{WantRunning: want},
			WantRunningSet: true,
		}); err != nil {
			return err
		}
	}
	return nil
}
