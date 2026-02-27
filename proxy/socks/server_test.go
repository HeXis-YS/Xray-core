package socks

import (
	gonet "net"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestLocalAddressFromAddr(t *testing.T) {
	testCases := []struct {
		name   string
		input  gonet.Addr
		output net.Address
	}{
		{
			name:   "nil",
			input:  nil,
			output: net.AnyIP,
		},
		{
			name: "tcp",
			input: &gonet.TCPAddr{
				IP: gonet.IPv4(127, 0, 0, 1),
			},
			output: net.IPAddress([]byte{127, 0, 0, 1}),
		},
		{
			name: "unix",
			input: &gonet.UnixAddr{
				Name: "/tmp/xray.sock",
				Net:  "unix",
			},
			output: net.AnyIP,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := localAddressFromAddr(tc.input)
			if got.String() != tc.output.String() {
				t.Fatalf("localAddressFromAddr() = %v, want %v", got, tc.output)
			}
		})
	}
}
