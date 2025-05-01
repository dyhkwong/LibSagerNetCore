package stun

import (
	"net"
	"strconv"

	"github.com/ccding/go-stun/stun"
	"github.com/wzshiming/socks5"
)

func setupPacketConn(useSOCKS5 bool, addrStr string, socksPort int) (net.PacketConn, error) {
	if useSOCKS5 {
		dialer, _ := socks5.NewDialer("socks5h://127.0.0.1:" + strconv.Itoa(socksPort))
		conn, err := dialer.Dial("udp", addrStr)
		if err != nil {
			return nil, err
		}
		return conn.(*socks5.UDPConn), nil
	} else {
		return net.ListenUDP("udp", nil)
	}
}

// RFC 5780
func Test(addrStr string, useSOCKS5 bool, socksPort int) (*stun.NATBehavior, error) {
	packetConn, err := setupPacketConn(useSOCKS5, addrStr, socksPort)
	if err != nil {
		return nil, err
	}
	client := stun.NewClientWithConnection(packetConn)
	client.SetServerAddr(addrStr)
	return client.BehaviorTest()
}

// RFC 3489
func TestLegacy(addrStr string, useSOCKS5 bool, socksPort int) (stun.NATType, *stun.Host, error) {
	packetConn, err := setupPacketConn(useSOCKS5, addrStr, socksPort)
	if err != nil {
		return 0, nil, err
	}
	client := stun.NewClientWithConnection(packetConn)
	client.SetServerAddr(addrStr)
	return client.Discover()
}
