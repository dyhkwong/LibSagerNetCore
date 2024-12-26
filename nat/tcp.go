package nat

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"libcore/clash/common/cache"
	"libcore/comm"
)

type tcpForwarder struct {
	tun       *SystemTun
	port4     uint16
	port6     uint16
	listener4 *net.TCPListener
	listener6 *net.TCPListener
	sessions  *cache.LruCache
}

func newTcpForwarder(tun *SystemTun) (*tcpForwarder, error) {
	tcpForwarder := &tcpForwarder{
		tun:      tun,
		sessions: cache.New(cache.WithAge(300), cache.WithUpdateAgeOnGet()),
	}
	if tun.ipv6Mode != comm.IPv6Only {
		address := &net.TCPAddr{}
		address.IP = net.IP(vlanClient4.AsSlice())
		listener, err := net.ListenTCP("tcp4", address)
		if err != nil {
			return nil, newError("failed to create tcp forwarder at ", address.IP).Base(err)
		}
		tcpForwarder.listener4 = listener
		tcpForwarder.port4 = uint16(listener.Addr().(*net.TCPAddr).Port)
		newError("tcp forwarder started at ", listener.Addr().(*net.TCPAddr)).AtDebug().WriteToLog()
	}
	if tun.ipv6Mode != comm.IPv6Disable {
		address := &net.TCPAddr{}
		address.IP = net.IP(vlanClient6.AsSlice())
		listener, err := net.ListenTCP("tcp6", address)
		if err != nil {
			return nil, newError("failed to create tcp forwarder at ", address.IP).Base(err)
		}
		tcpForwarder.listener6 = listener
		tcpForwarder.port6 = uint16(listener.Addr().(*net.TCPAddr).Port)
		newError("tcp forwarder started at ", listener.Addr().(*net.TCPAddr)).AtDebug().WriteToLog()
	}
	return tcpForwarder, nil
}

func (t *tcpForwarder) dispatch(listener *net.TCPListener) (bool, error) {
	conn, err := listener.AcceptTCP()
	if err != nil {
		return true, err
	}
	addr := conn.RemoteAddr().(*net.TCPAddr)
	key := peerKey{tcpip.AddrFromSlice(addr.IP), uint16(addr.Port)}
	var session *peerValue
	iSession, ok := t.sessions.Get(peerKey{key.destinationAddress, key.sourcePort})
	if ok {
		session = iSession.(*peerValue)
	} else {
		conn.Close()
		return false, newError("dropped unknown tcp session with source port ", key.sourcePort, " to destination address ", key.destinationAddress)
	}

	source := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(session.sourceAddress.AsSlice()),
		Port:    v2rayNet.Port(key.sourcePort),
		Network: v2rayNet.Network_TCP,
	}
	destination := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(key.destinationAddress.AsSlice()),
		Port:    v2rayNet.Port(session.destinationPort),
		Network: v2rayNet.Network_TCP,
	}

	go func() {
		t.tun.handler.NewConnection(source, destination, conn)
		time.Sleep(time.Second * 5)
		t.sessions.Delete(key)
	}()

	return false, nil
}

func (t *tcpForwarder) dispatchLoop(listener *net.TCPListener) {
	for {
		stop, err := t.dispatch(listener)
		if err != nil {
			e := newError("dispatch tcp conn failed").Base(err)
			e.WriteToLog()
			if stop {
				return
			}
		}
	}
}

func (t *tcpForwarder) processIPv4(ipHdr header.IPv4, tcpHdr header.TCP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := tcpHdr.SourcePort()
	destinationPort := tcpHdr.DestinationPort()

	var session *peerValue

	if sourcePort != t.port4 {

		key := peerKey{destinationAddress, sourcePort}
		iSession, ok := t.sessions.Get(key)
		if ok {
			session = iSession.(*peerValue)
		} else {
			session = &peerValue{sourceAddress, destinationPort}
			t.sessions.Set(key, session)
		}

		ipHdr.SetSourceAddress(destinationAddress)
		ipHdr.SetDestinationAddress(vlanClient4)
		tcpHdr.SetDestinationPort(t.port4)

	} else {

		iSession, ok := t.sessions.Get(peerKey{destinationAddress, destinationPort})
		if ok {
			session = iSession.(*peerValue)
		} else {
			logrus.Warn("unknown tcp session with source port ", destinationPort, " to destination address ", destinationAddress)
			return
		}
		ipHdr.SetSourceAddress(destinationAddress)
		tcpHdr.SetSourcePort(session.destinationPort)
		ipHdr.SetDestinationAddress(session.sourceAddress)
	}

	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), uint16(len(tcpHdr))),
		checksum.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) processIPv6(ipHdr header.IPv6, tcpHdr header.TCP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := tcpHdr.SourcePort()
	destinationPort := tcpHdr.DestinationPort()

	var session *peerValue

	if sourcePort != t.port6 {

		key := peerKey{destinationAddress, sourcePort}
		iSession, ok := t.sessions.Get(key)
		if ok {
			session = iSession.(*peerValue)
		} else {
			session = &peerValue{sourceAddress, destinationPort}
			t.sessions.Set(key, session)
		}

		ipHdr.SetSourceAddress(destinationAddress)
		ipHdr.SetDestinationAddress(vlanClient6)
		tcpHdr.SetDestinationPort(t.port6)

	} else {

		iSession, ok := t.sessions.Get(peerKey{destinationAddress, destinationPort})
		if ok {
			session = iSession.(*peerValue)
		} else {
			logrus.Warn("unknown tcp session with source port ", destinationPort, " to destination address ", destinationAddress)
			return
		}

		ipHdr.SetSourceAddress(destinationAddress)
		tcpHdr.SetSourcePort(session.destinationPort)
		ipHdr.SetDestinationAddress(session.sourceAddress)
	}

	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), uint16(len(tcpHdr))),
		checksum.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) Close() error {
	_ = t.listener4.Close()
	_ = t.listener6.Close()
	return nil
}
