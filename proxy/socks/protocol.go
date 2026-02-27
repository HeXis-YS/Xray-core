package socks

import (
	"encoding/binary"
	"io"

	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

const (
	socks5Version = 0x05
	socks4Version = 0x04

	cmdTCPConnect        = 0x01
	cmdTCPBind           = 0x02
	cmdUDPAssociate      = 0x03
	cmdUDPAssociateInTCP = 0x05
	cmdTorResolve        = 0xF0
	cmdTorResolvePTR     = 0xF1

	socks4RequestGranted  = 90
	socks4RequestRejected = 91

	authNotRequired = 0x00
	// authGssAPI           = 0x01
	authPassword         = 0x02
	authNoMatchingMethod = 0xFF

	statusSuccess        = 0x00
	statusCmdNotSupport  = 0x07
	statusAddrNotSupport = 0x08
)

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x04, net.AddressFamilyIPv6),
	protocol.AddressFamilyByte(0x03, net.AddressFamilyDomain),
)

type ServerSession struct {
	config       *ServerConfig
	address      net.Address
	port         net.Port
	localAddress net.Address
}

type Socks5UDPRequest struct {
	UDPInTCP bool
}

func (s *ServerSession) handshake4(cmd byte, reader io.Reader, writer io.Writer) (*protocol.RequestHeader, *Socks5UDPRequest, error) {
	if s.config.AuthType == AuthType_PASSWORD {
		writeSocks4Response(writer, socks4RequestRejected, net.AnyIP, net.Port(0))
		return nil, nil, errors.New("socks 4 is not allowed when auth is required.")
	}

	var port net.Port
	var address net.Address

	{
		buffer := buf.StackNew()
		if _, err := buffer.ReadFullFrom(reader, 6); err != nil {
			buffer.Release()
			return nil, nil, errors.New("insufficient header").Base(err)
		}
		port = net.PortFromBytes(buffer.BytesRange(0, 2))
		address = net.IPAddress(buffer.BytesRange(2, 6))
		buffer.Release()
	}

	if _, err := ReadUntilNull(reader); /* user id */ err != nil {
		return nil, nil, err
	}
	if address.IP()[0] == 0x00 {
		domain, err := ReadUntilNull(reader)
		if err != nil {
			return nil, nil, errors.New("failed to read domain for socks 4a").Base(err)
		}
		address = net.ParseAddress(domain)
	}

	switch cmd {
	case cmdTCPConnect:
		request := &protocol.RequestHeader{
			Command: protocol.RequestCommandTCP,
			Address: address,
			Port:    port,
			Version: socks4Version,
		}
		if err := writeSocks4Response(writer, socks4RequestGranted, net.AnyIP, net.Port(0)); err != nil {
			return nil, nil, err
		}
		return request, nil, nil
	default:
		writeSocks4Response(writer, socks4RequestRejected, net.AnyIP, net.Port(0))
		return nil, nil, errors.New("unsupported command: ", cmd)
	}
}

func (s *ServerSession) auth5(nMethod byte, reader io.Reader, writer io.Writer) (username string, err error) {
	buffer := buf.StackNew()
	defer buffer.Release()

	if _, err = buffer.ReadFullFrom(reader, int32(nMethod)); err != nil {
		return "", errors.New("failed to read auth methods").Base(err)
	}

	var expectedAuth byte = authNotRequired
	if s.config.AuthType == AuthType_PASSWORD {
		expectedAuth = authPassword
	}

	if !hasAuthMethod(expectedAuth, buffer.BytesRange(0, int32(nMethod))) {
		writeSocks5AuthenticationResponse(writer, socks5Version, authNoMatchingMethod)
		return "", errors.New("no matching auth method")
	}

	if err := writeSocks5AuthenticationResponse(writer, socks5Version, expectedAuth); err != nil {
		return "", errors.New("failed to write auth response").Base(err)
	}

	if expectedAuth == authPassword {
		username, password, err := ReadUsernamePassword(reader)
		if err != nil {
			return "", errors.New("failed to read username and password for authentication").Base(err)
		}

		if !s.config.HasAccount(username, password) {
			writeSocks5AuthenticationResponse(writer, 0x01, 0xFF)
			return "", errors.New("invalid username or password")
		}

		if err := writeSocks5AuthenticationResponse(writer, 0x01, 0x00); err != nil {
			return "", errors.New("failed to write auth response").Base(err)
		}
		return username, nil
	}

	return "", nil
}

func (s *ServerSession) handshake5(nMethod byte, reader io.Reader, writer io.Writer) (*protocol.RequestHeader, *Socks5UDPRequest, error) {
	var (
		username string
		err      error
	)
	if username, err = s.auth5(nMethod, reader, writer); err != nil {
		return nil, nil, err
	}

	var cmd byte
	{
		buffer := buf.StackNew()
		if _, err := buffer.ReadFullFrom(reader, 3); err != nil {
			buffer.Release()
			return nil, nil, errors.New("failed to read request").Base(err)
		}
		cmd = buffer.Byte(1)
		buffer.Release()
	}

	request := new(protocol.RequestHeader)
	requestInTCP := new(Socks5UDPRequest)
	if username != "" {
		request.User = &protocol.MemoryUser{Email: username}
	}
	switch cmd {
	case cmdTCPConnect, cmdTorResolve, cmdTorResolvePTR:
		// We don't have a solution for Tor case now. Simply treat it as connect command.
		request.Command = protocol.RequestCommandTCP
	case cmdUDPAssociate:
		if !s.config.UdpEnabled {
			writeSocks5Response(writer, statusCmdNotSupport, net.AnyIP, net.Port(0))
			return nil, nil, errors.New("UDP is not enabled.")
		}
		request.Command = protocol.RequestCommandUDP
	case cmdUDPAssociateInTCP:
		if !s.config.UdpEnabled {
			writeSocks5Response(writer, statusCmdNotSupport, net.AnyIP, net.Port(0))
			return nil, nil, errors.New("UDP is not enabled.")
		}
		if !s.config.UdpOverTcp {
			writeSocks5Response(writer, statusCmdNotSupport, net.AnyIP, net.Port(0))
			return nil, nil, errors.New("UDP in TCP is not enabled.")
		}
		request.Command = protocol.RequestCommandUDP
		requestInTCP.UDPInTCP = true
	case cmdTCPBind:
		writeSocks5Response(writer, statusCmdNotSupport, net.AnyIP, net.Port(0))
		return nil, nil, errors.New("TCP bind is not supported.")
	default:
		writeSocks5Response(writer, statusCmdNotSupport, net.AnyIP, net.Port(0))
		return nil, nil, errors.New("unknown command ", cmd)
	}

	request.Version = socks5Version

	addr, port, err := addrParser.ReadAddressPort(nil, reader)
	if err != nil {
		return nil, nil, errors.New("failed to read address").Base(err)
	}
	request.Address = addr
	request.Port = port

	responseAddress := s.address
	responsePort := s.port
	// Some clients (including hev-socks5-core) only accept IPv4/IPv6 in
	// responses. For unix-listen inbounds, gateway address is a domain path,
	// so normalize it to an IP fallback.
	if responseAddress == nil || responseAddress.Family().IsDomain() {
		responseAddress = s.localAddress
		if responseAddress == nil || responseAddress.Family().IsDomain() {
			responseAddress = net.AnyIP
		}
	}
	//nolint:gocritic // Use if else chain for clarity
	if request.Command == protocol.RequestCommandUDP {
		if s.config.Address != nil {
			// Use configured IP as remote address in the response to UDP Associate
			responseAddress = s.config.Address.AsAddress()
		} else {
			// Use conn.LocalAddr() IP as remote address in the response by default
			responseAddress = s.localAddress
		}
		if responseAddress.Family().IsDomain() {
			// Socks5 doesn't support domain in response to UDP Associate
			writeSocks5Response(writer, statusAddrNotSupport, net.AnyIP, net.Port(0))
			return nil, nil, errors.New("domain is not supported in response to UDP Associate")
		}
	}
	if err := writeSocks5Response(writer, statusSuccess, responseAddress, responsePort); err != nil {
		return nil, nil, err
	}
	if !requestInTCP.UDPInTCP {
		requestInTCP = nil
	}
	return request, requestInTCP, nil
}

// Handshake performs a Socks4/4a/5 handshake.
func (s *ServerSession) Handshake(reader io.Reader, writer io.Writer) (*protocol.RequestHeader, *Socks5UDPRequest, error) {
	buffer := buf.StackNew()
	if _, err := buffer.ReadFullFrom(reader, 2); err != nil {
		buffer.Release()
		return nil, nil, errors.New("insufficient header").Base(err)
	}

	version := buffer.Byte(0)
	cmd := buffer.Byte(1)
	buffer.Release()

	switch version {
	case socks4Version:
		return s.handshake4(cmd, reader, writer)
	case socks5Version:
		return s.handshake5(cmd, reader, writer)
	default:
		return nil, nil, errors.New("unknown Socks version: ", version)
	}
}

// ReadUsernamePassword reads Socks 5 username/password message from the given reader.
// +----+------+----------+------+----------+
// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// +----+------+----------+------+----------+
// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
// +----+------+----------+------+----------+
func ReadUsernamePassword(reader io.Reader) (string, string, error) {
	buffer := buf.StackNew()
	defer buffer.Release()

	if _, err := buffer.ReadFullFrom(reader, 2); err != nil {
		return "", "", err
	}
	nUsername := int32(buffer.Byte(1))

	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, nUsername); err != nil {
		return "", "", err
	}
	username := buffer.String()

	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return "", "", err
	}
	nPassword := int32(buffer.Byte(0))

	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, nPassword); err != nil {
		return "", "", err
	}
	password := buffer.String()
	return username, password, nil
}

// ReadUntilNull reads content from given reader, until a null (0x00) byte.
func ReadUntilNull(reader io.Reader) (string, error) {
	b := buf.StackNew()
	defer b.Release()

	for {
		_, err := b.ReadFullFrom(reader, 1)
		if err != nil {
			return "", err
		}
		if b.Byte(b.Len()-1) == 0x00 {
			b.Resize(0, b.Len()-1)
			return b.String(), nil
		}
		if b.IsFull() {
			return "", errors.New("buffer overrun")
		}
	}
}

func hasAuthMethod(expectedAuth byte, authCandidates []byte) bool {
	for _, a := range authCandidates {
		if a == expectedAuth {
			return true
		}
	}
	return false
}

func writeSocks5AuthenticationResponse(writer io.Writer, version byte, auth byte) error {
	return buf.WriteAllBytes(writer, []byte{version, auth}, nil)
}

func writeSocks5Response(writer io.Writer, errCode byte, address net.Address, port net.Port) error {
	buffer := buf.New()
	defer buffer.Release()

	common.Must2(buffer.Write([]byte{socks5Version, errCode, 0x00 /* reserved */}))
	if err := addrParser.WriteAddressPort(buffer, address, port); err != nil {
		return err
	}

	return buf.WriteAllBytes(writer, buffer.Bytes(), nil)
}

func writeSocks4Response(writer io.Writer, errCode byte, address net.Address, port net.Port) error {
	buffer := buf.StackNew()
	defer buffer.Release()

	common.Must(buffer.WriteByte(0x00))
	common.Must(buffer.WriteByte(errCode))
	portBytes := buffer.Extend(2)
	binary.BigEndian.PutUint16(portBytes, port.Value())
	common.Must2(buffer.Write(address.IP()))
	return buf.WriteAllBytes(writer, buffer.Bytes(), nil)
}

func DecodeUDPPacket(packet *buf.Buffer) (*protocol.RequestHeader, error) {
	if packet.Len() < 5 {
		return nil, errors.New("insufficient length of packet.")
	}
	request := &protocol.RequestHeader{
		Version: socks5Version,
		Command: protocol.RequestCommandUDP,
	}

	// packet[0] and packet[1] are reserved
	if packet.Byte(2) != 0 /* fragments */ {
		return nil, errors.New("discarding fragmented payload.")
	}

	packet.Advance(3)

	addr, port, err := addrParser.ReadAddressPort(nil, packet)
	if err != nil {
		return nil, errors.New("failed to read UDP header").Base(err)
	}
	request.Address = addr
	request.Port = port
	return request, nil
}

func EncodeUDPPacket(request *protocol.RequestHeader, data []byte) (*buf.Buffer, error) {
	b := buf.New()
	common.Must2(b.Write([]byte{0, 0, 0 /* Fragment */}))
	if err := addrParser.WriteAddressPort(b, request.Address, request.Port); err != nil {
		b.Release()
		return nil, err
	}
	// if data is too large, return an empty buffer (drop too big data)
	if b.Available() < int32(len(data)) {
		b.Clear()
		return b, nil
	}
	common.Must2(b.Write(data))
	return b, nil
}

func DecodeUDPInTCPPacket(packet *buf.Buffer) (*protocol.RequestHeader, error) {
	if packet.Len() < 5 {
		return nil, errors.New("insufficient length of packet.")
	}
	request := &protocol.RequestHeader{
		Version: socks5Version,
		Command: protocol.RequestCommandUDP,
	}

	dataLength := int32(binary.BigEndian.Uint16(packet.BytesRange(0, 2)))
	headerLength := int32(packet.Byte(2))
	if headerLength < 5 {
		return nil, errors.New("invalid udp-in-tcp header length.")
	}
	if packet.Len() != dataLength+headerLength {
		return nil, errors.New("invalid udp-in-tcp packet length.")
	}

	packet.Advance(3)
	beforeLen := packet.Len()
	addr, port, err := addrParser.ReadAddressPort(nil, packet)
	if err != nil {
		return nil, errors.New("failed to read UDP-in-TCP header").Base(err)
	}
	if beforeLen-packet.Len() != headerLength-3 {
		return nil, errors.New("invalid udp-in-tcp address length.")
	}
	if packet.Len() != dataLength {
		return nil, errors.New("invalid udp-in-tcp payload length.")
	}
	request.Address = addr
	request.Port = port
	return request, nil
}

func EncodeUDPInTCPPacket(request *protocol.RequestHeader, data []byte) (*buf.Buffer, error) {
	if len(data) > 0xFFFF {
		return nil, errors.New("udp-in-tcp payload too large: ", len(data))
	}
	addrBuf := buf.New()
	defer addrBuf.Release()
	if err := addrParser.WriteAddressPort(addrBuf, request.Address, request.Port); err != nil {
		return nil, err
	}
	headerLength := int32(3 + addrBuf.Len())
	if headerLength > 0xFF {
		return nil, errors.New("udp-in-tcp header too large: ", headerLength)
	}

	packet := buf.New()
	header := packet.Extend(3)
	binary.BigEndian.PutUint16(header[:2], uint16(len(data)))
	header[2] = byte(headerLength)
	common.Must2(packet.Write(addrBuf.Bytes()))
	// if data is too large, return an empty buffer (drop too big data)
	if packet.Available() < int32(len(data)) {
		packet.Clear()
		return packet, nil
	}
	common.Must2(packet.Write(data))
	return packet, nil
}

type UDPReader struct {
	Reader       io.Reader
	Request      *protocol.RequestHeader
	RequestInTCP *Socks5UDPRequest
}

func NewUDPReader(reader io.Reader, request *protocol.RequestHeader, requestInTCP *Socks5UDPRequest) *UDPReader {
	return &UDPReader{
		Reader:       reader,
		Request:      request,
		RequestInTCP: requestInTCP,
	}
}

func (r *UDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer := buf.New()
	if requestInTCP := r.RequestInTCP; requestInTCP != nil && requestInTCP.UDPInTCP {
		frameHeader := [3]byte{}
		if _, err := io.ReadFull(r.Reader, frameHeader[:]); err != nil {
			buffer.Release()
			return nil, err
		}
		dataLength := int32(binary.BigEndian.Uint16(frameHeader[:2]))
		headerLength := int32(frameHeader[2])
		if headerLength < 5 {
			buffer.Release()
			return nil, errors.New("invalid udp-in-tcp header length: ", headerLength)
		}
		frameLength := headerLength + dataLength
		common.Must2(buffer.Write(frameHeader[:]))
		if _, err := buffer.ReadFullFrom(r.Reader, frameLength-3); err != nil {
			buffer.Release()
			return nil, err
		}
	} else {
		if _, err := buffer.ReadFrom(r.Reader); err != nil {
			buffer.Release()
			return nil, err
		}
	}
	var (
		u   *protocol.RequestHeader
		err error
	)
	if requestInTCP := r.RequestInTCP; requestInTCP != nil && requestInTCP.UDPInTCP {
		u, err = DecodeUDPInTCPPacket(buffer)
	} else {
		u, err = DecodeUDPPacket(buffer)
	}
	if err != nil {
		buffer.Release()
		return nil, err
	}
	dest := u.Destination()
	buffer.UDP = &dest
	return buf.MultiBuffer{buffer}, nil
}

type UDPWriter struct {
	Writer       io.Writer
	Request      *protocol.RequestHeader
	RequestInTCP *Socks5UDPRequest
}

func NewUDPWriter(writer io.Writer, request *protocol.RequestHeader, requestInTCP *Socks5UDPRequest) *UDPWriter {
	return &UDPWriter{
		Writer:       writer,
		Request:      request,
		RequestInTCP: requestInTCP,
	}
}

func (w *UDPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		request := w.Request
		if b.UDP != nil {
			request = &protocol.RequestHeader{
				Address: b.UDP.Address,
				Port:    b.UDP.Port,
			}
		}
		var (
			packet *buf.Buffer
			err    error
		)
		if requestInTCP := w.RequestInTCP; requestInTCP != nil && requestInTCP.UDPInTCP {
			packet, err = EncodeUDPInTCPPacket(request, b.Bytes())
		} else {
			packet, err = EncodeUDPPacket(request, b.Bytes())
		}
		b.Release()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		_, err = w.Writer.Write(packet.Bytes())
		packet.Release()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return nil
}

func ClientHandshake(request *protocol.RequestHeader, reader io.Reader, writer io.Writer) (*protocol.RequestHeader, *Socks5UDPRequest, error) {
	authByte := byte(authNotRequired)
	if request.User != nil {
		authByte = byte(authPassword)
	}

	b := buf.New()
	defer b.Release()

	common.Must2(b.Write([]byte{socks5Version, 0x01, authByte}))
	if err := buf.WriteAllBytes(writer, b.Bytes(), nil); err != nil {
		return nil, nil, err
	}

	b.Clear()
	if _, err := b.ReadFullFrom(reader, 2); err != nil {
		return nil, nil, err
	}

	if b.Byte(0) != socks5Version {
		return nil, nil, errors.New("unexpected server version: ", b.Byte(0)).AtWarning()
	}
	if b.Byte(1) != authByte {
		return nil, nil, errors.New("auth method not supported.").AtWarning()
	}

	if authByte == authPassword {
		b.Clear()
		account := request.User.Account.(*Account)
		common.Must(b.WriteByte(0x01))
		common.Must(b.WriteByte(byte(len(account.Username))))
		common.Must2(b.WriteString(account.Username))
		common.Must(b.WriteByte(byte(len(account.Password))))
		common.Must2(b.WriteString(account.Password))
		if err := buf.WriteAllBytes(writer, b.Bytes(), nil); err != nil {
			return nil, nil, err
		}

		b.Clear()
		if _, err := b.ReadFullFrom(reader, 2); err != nil {
			return nil, nil, err
		}
		if b.Byte(1) != 0x00 {
			return nil, nil, errors.New("server rejects account: ", b.Byte(1))
		}
	}

	b.Clear()

	command := byte(cmdTCPConnect)
	requestInTCP := new(Socks5UDPRequest)
	if request.Command == protocol.RequestCommandUDP {
		command = byte(cmdUDPAssociate)
		if request.Address.Family().IsDomain() {
			// Keep both trigger domains for compatibility, but CMD=0x05 always uses
			// SOCKS UDP-in-TCP framing (MSGLEN/HDRLEN/ATYP...).
			if request.Address.Domain() == uot.MagicAddress || request.Address.Domain() == uot.LegacyMagicAddress {
				command = byte(cmdUDPAssociateInTCP)
				requestInTCP.UDPInTCP = true
			}
		}
	}
	common.Must2(b.Write([]byte{socks5Version, command, 0x00 /* reserved */}))
	if request.Command == protocol.RequestCommandUDP && command == byte(cmdUDPAssociate) {
		common.Must2(b.Write([]byte{1, 0, 0, 0, 0, 0, 0 /* RFC 1928 */}))
	} else {
		if err := addrParser.WriteAddressPort(b, request.Address, request.Port); err != nil {
			return nil, nil, err
		}
	}

	if err := buf.WriteAllBytes(writer, b.Bytes(), nil); err != nil {
		return nil, nil, err
	}

	b.Clear()
	if _, err := b.ReadFullFrom(reader, 3); err != nil {
		return nil, nil, err
	}

	resp := b.Byte(1)
	if resp != 0x00 {
		return nil, nil, errors.New("server rejects request: ", resp)
	}

	b.Clear()

	address, port, err := addrParser.ReadAddressPort(b, reader)
	if err != nil {
		return nil, nil, err
	}

	if request.Command == protocol.RequestCommandUDP {
		udpRequest := &protocol.RequestHeader{
			Version: socks5Version,
			Command: protocol.RequestCommandUDP,
			Address: address,
			Port:    port,
		}
		if !requestInTCP.UDPInTCP {
			requestInTCP = nil
		}
		return udpRequest, requestInTCP, nil
	}

	return nil, nil, nil
}
