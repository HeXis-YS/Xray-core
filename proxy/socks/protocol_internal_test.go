package socks

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func TestHandshake5UnixListenResponseUsesIP(t *testing.T) {
	session := &ServerSession{
		config: &ServerConfig{
			AuthType: AuthType_NO_AUTH,
		},
		address:      net.DomainAddress("@socks"),
		port:         0,
		localAddress: net.AnyIP,
	}

	input := bytes.NewBuffer(nil)
	// Greeting: VER=5, NMETHODS=1, METHODS=[NO_AUTH].
	input.Write([]byte{0x05, 0x01, 0x00})
	// Request: VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, DST=127.0.0.1:80.
	input.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80})

	output := bytes.NewBuffer(nil)
	request, requestInTCP, err := session.Handshake(input, output)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if request.Command != protocol.RequestCommandTCP {
		t.Fatalf("unexpected command: %v", request.Command)
	}
	if requestInTCP != nil {
		t.Fatalf("unexpected UDP-in-TCP request: %+v", requestInTCP)
	}

	resp := output.Bytes()
	// Output contains auth response first: [VER, METHOD], then request response.
	if len(resp) < 6 {
		t.Fatalf("short response: %v", resp)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected auth response: %v", resp[:2])
	}
	if resp[2] != 0x05 || resp[3] != 0x00 {
		t.Fatalf("unexpected request response header: %v", resp[2:4])
	}
	if resp[5] != 0x01 && resp[5] != 0x04 {
		t.Fatalf("response ATYP must be IPv4/IPv6, got: 0x%02x", resp[5])
	}
}
