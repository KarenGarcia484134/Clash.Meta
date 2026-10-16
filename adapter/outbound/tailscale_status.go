//go:build with_gvisor && !no_tailscale

// FlClash patch: read-only access to the tsnet node for status pages.
// Kept in its own file so syncing with upstream never conflicts.

package outbound

import (
	"context"
	"errors"

	"github.com/metacubex/tailscale/ipn/ipnstate"
)

var ErrTailscaleNotStarted = errors.New("tailscale node is not started")

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
