//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"testing"
)

func TestTailscaleStatusBeforeStart(t *testing.T) {
	node := &Tailscale{}
	if node.Started() {
		t.Fatal("a fresh node must not report started")
	}
	if _, err := node.Status(context.Background()); !errors.Is(err, ErrTailscaleNotStarted) {
		t.Fatalf("expected ErrTailscaleNotStarted, got %v", err)
	}
}

func TestTailscaleStatusFromOption(t *testing.T) {
	node, err := NewTailscale(TailscaleOption{
		BasicOption: BasicOption{},
		Name:        "ts",
		StateDir:    t.TempDir(),
	})
	if err != nil {
		t.Skipf("tailscale outbound unavailable: %v", err)
	}
	defer node.Close()
	if _, err := node.Status(context.Background()); !errors.Is(err, ErrTailscaleNotStarted) {
		t.Fatalf("expected ErrTailscaleNotStarted, got %v", err)
	}
}
