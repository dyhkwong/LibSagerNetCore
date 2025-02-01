package stun

import (
	"context"
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

func resolveDNS(host string, dnsPort int) (net.IP, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := new(net.Dialer)
			return dialer.DialContext(ctx, network, "127.0.0.1:"+strconv.Itoa(dnsPort))
		},
	}
	ips, err := resolver.LookupIP(context.Background(), "ip", host)
	if err != nil {
		return nil, err
	}
	return ips[0], nil
}

// RFC 5780
func Test(addrStr string, useSOCKS5 bool, socksPort int, dnsPort int) (*stun.NATBehavior, error) {
	if addrStr == "" {
		addrStr = "stun.syncthing.net:3478"
	}
	host, port, err := net.SplitHostPort(addrStr)
	if err != nil {
		return nil, err
	}
	packetConn, err := setupPacketConn(useSOCKS5, addrStr, socksPort)
	if err != nil {
		return nil, err
	}
	if useSOCKS5 && net.ParseIP(host) == nil {
		ip, err := resolveDNS(host, dnsPort)
		if err != nil {
			return nil, err
		}
		addrStr = net.JoinHostPort(ip.String(), port)
	}
	client := stun.NewClientWithConnection(packetConn)
	client.SetServerAddr(addrStr)
	return client.BehaviorTest()
}

// RFC 3489
func TestLegacy(addrStr string, useSOCKS5 bool, socksPort int, dnsPort int) (stun.NATType, *stun.Host, error) {
	if addrStr == "" {
		addrStr = "stun.syncthing.net:3478"
	}
	host, port, err := net.SplitHostPort(addrStr)
	if err != nil {
		return 0, nil, err
	}
	packetConn, err := setupPacketConn(useSOCKS5, addrStr, socksPort)
	if err != nil {
		return 0, nil, err
	}
	if useSOCKS5 && net.ParseIP(host) == nil {
		ip, err := resolveDNS(host, dnsPort)
		if err != nil {
			return 0, nil, err
		}
		addrStr = net.JoinHostPort(ip.String(), port)
	}
	client := stun.NewClientWithConnection(packetConn)
	client.SetServerAddr(addrStr)
	return client.Discover()
}
