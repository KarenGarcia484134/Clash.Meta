//go:build with_gvisor && !no_tailscale

package outbound

import (
	"net"
	"testing"

	"github.com/metacubex/tailscale/net/netmon"
)

func cidrAddr(s string) net.Addr {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	ipNet.IP = ip
	return ipNet
}

func TestFilterTailscaleInterfaces(t *testing.T) {
	ifaces := []netmon.Interface{
		{
			Interface: &net.Interface{Index: 1, Name: "tun0", Flags: net.FlagUp},
			AltAddrs:  []net.Addr{cidrAddr("198.18.0.1/30"), cidrAddr("fe80::1/64")},
		},
		{
			Interface: &net.Interface{Index: 2, Name: "tun1", Flags: net.FlagUp},
			AltAddrs:  []net.Addr{cidrAddr("fdfe:dcba:9876::1/126")},
		},
		{
			Interface: &net.Interface{Index: 3, Name: "wlan0", Flags: net.FlagUp},
			AltAddrs:  []net.Addr{cidrAddr("192.168.1.10/24")},
		},
		{
			Interface: &net.Interface{Index: 4, Name: "eth0", Flags: net.FlagUp},
			AltAddrs:  []net.Addr{cidrAddr("10.0.0.2/24"), cidrAddr("2001:db8::2/64")},
		},
		{
			Interface: &net.Interface{Index: 5, Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
			AltAddrs:  []net.Addr{cidrAddr("127.0.0.1/8")},
		},
	}

	got := filterTailscaleInterfaces(ifaces)
	want := []string{"wlan0", "eth0", "lo"}
	if len(got) != len(want) {
		t.Fatalf("filtered count = %d, want %d", len(got), len(want))
	}
	for i, name := range want {
		if got[i].Name != name {
			t.Fatalf("filtered[%d].Name = %q, want %q", i, got[i].Name, name)
		}
	}
}

func TestTailscaleInterfaceGetterActive(t *testing.T) {
	ifaces, err := netmon.GetInterfaceList()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		if hasMihomoTUNAddr(addrs) {
			t.Fatalf("netmon.GetInterfaceList returned TUN interface %q", iface.Name)
		}
	}
}
