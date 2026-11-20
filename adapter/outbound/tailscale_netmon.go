//go:build with_gvisor && !no_tailscale

package outbound

import (
	"net"
	"net/netip"
	"runtime"

	"github.com/metacubex/mihomo/component/iface/anet"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tailscale/net/netmon"
)

var mihomoTUNPrefixes = []netip.Prefix{
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fdfe:dcba:9876::/48"),
}

func isMihomoTUNAddr(addr net.Addr) bool {
	var raw net.IP
	switch v := addr.(type) {
	case *net.IPNet:
		raw = v.IP
	case *net.IPAddr:
		raw = v.IP
	default:
		return false
	}
	ip, ok := netip.AddrFromSlice(raw)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range mihomoTUNPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func hasMihomoTUNAddr(addrs []net.Addr) bool {
	for _, addr := range addrs {
		if isMihomoTUNAddr(addr) {
			return true
		}
	}
	return false
}

func filterTailscaleInterfaces(ifaces []netmon.Interface) []netmon.Interface {
	filtered := make([]netmon.Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err == nil && hasMihomoTUNAddr(addrs) {
			continue
		}
		filtered = append(filtered, iface)
	}
	return filtered
}

func tailscaleInterfaces() ([]netmon.Interface, error) {
	var raw []netmon.Interface
	if runtime.GOOS == "android" {
		ifaces, err := anet.Interfaces()
		if err != nil {
			log.Warnln("[Tailscale] anet.Interfaces failed: %v", err)
			return nil, err
		}
		raw = make([]netmon.Interface, 0, len(ifaces))
		for _, iff := range ifaces {
			addrs, err := anet.InterfaceAddrsByInterface(&iff)
			if err != nil {
				log.Warnln("[Tailscale] anet.InterfaceAddrsByInterface(%v) failed: %v", iff.Name, err)
				continue
			}
			raw = append(raw, netmon.Interface{
				Interface: &net.Interface{
					Index:        iff.Index,
					MTU:          iff.MTU,
					Name:         iff.Name,
					HardwareAddr: iff.HardwareAddr,
					Flags:        iff.Flags,
				},
				AltAddrs: addrs,
			})
		}
	} else {
		ifs, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		raw = make([]netmon.Interface, len(ifs))
		for i := range ifs {
			iface := ifs[i]
			addrs, err := iface.Addrs()
			if err != nil {
				addrs = nil
			}
			raw[i] = netmon.Interface{
				Interface: &iface,
				AltAddrs:  addrs,
			}
		}
	}
	return filterTailscaleInterfaces(raw), nil
}

// Runs after tailscale.go's init() (lexical filename order) so our filtered
// getter replaces upstream's Android-only registration on every platform.
func init() {
	netmon.RegisterInterfaceGetter(tailscaleInterfaces)
}
