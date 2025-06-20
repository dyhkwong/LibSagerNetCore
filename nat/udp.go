package nat

import (
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (t *SystemTun) processIPv4UDP(ipHdr header.IPv4, hdr header.UDP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := hdr.SourcePort()
	destinationPort := hdr.DestinationPort()

	source := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(sourceAddress.AsSlice()),
		Port:    v2rayNet.Port(sourcePort),
		Network: v2rayNet.Network_UDP,
	}
	destination := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(destinationAddress.AsSlice()),
		Port:    v2rayNet.Port(destinationPort),
		Network: v2rayNet.Network_UDP,
	}

	ipHdr.SetDestinationAddress(sourceAddress)
	hdr.SetDestinationPort(sourcePort)

	ipHdrLength := ipHdr.HeaderLength()
	newHeader := make([]byte, ipHdrLength+header.UDPMinimumSize)
	copy(newHeader, ipHdr[:ipHdrLength+header.UDPMinimumSize])

	payload := hdr.Payload()
	data := make([]byte, len(payload))
	copy(data, payload)

	go t.handler.NewPacket(source, destination, data, func(bytes []byte, addr *v2rayNet.UDPAddr) (int, error) {
		var newSourceAddress tcpip.Address
		var newSourcePort uint16

		if addr != nil {
			newSourceAddress = tcpip.AddrFromSlice(addr.IP)
			newSourcePort = uint16(addr.Port)
		} else {
			newSourceAddress = destinationAddress
			newSourcePort = destinationPort
		}

		newIpHdr := header.IPv4(newHeader)
		newIpHdr.SetSourceAddress(newSourceAddress)
		newIpHdr.SetTotalLength(uint16(int(ipHdrLength+header.UDPMinimumSize) + len(bytes)))
		newIpHdr.SetChecksum(0)
		newIpHdr.SetChecksum(^newIpHdr.CalculateChecksum())

		udpHdr := header.UDP(newHeader[ipHdrLength:])
		udpHdr.SetSourcePort(newSourcePort)
		udpHdr.SetLength(uint16(header.UDPMinimumSize + len(bytes)))
		udpHdr.SetChecksum(0)
		udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(bytes, header.PseudoHeaderChecksum(header.UDPProtocolNumber, newSourceAddress, sourceAddress, uint16(header.UDPMinimumSize+len(bytes))))))

		payload := buffer.MakeWithData(newHeader)
		payload.Append(buffer.NewViewWithData(bytes))

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: payload,
		})
		err := t.writeRawPacket(pkt)
		pkt.DecRef()
		if err != nil {
			return 0, newError(err.String())
		}

		return len(bytes), nil
	})
}

func (t *SystemTun) processIPv6UDP(ipHdr header.IPv6, hdr header.UDP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := hdr.SourcePort()
	destinationPort := hdr.DestinationPort()

	source := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(sourceAddress.AsSlice()),
		Port:    v2rayNet.Port(sourcePort),
		Network: v2rayNet.Network_UDP,
	}
	destination := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(destinationAddress.AsSlice()),
		Port:    v2rayNet.Port(destinationPort),
		Network: v2rayNet.Network_UDP,
	}

	ipHdr.SetDestinationAddress(sourceAddress)
	hdr.SetDestinationPort(sourcePort)

	ipHdrLength := uint16(len(ipHdr)) - ipHdr.PayloadLength()
	newHeader := make([]byte, ipHdrLength+header.UDPMinimumSize)
	copy(newHeader, ipHdr[:ipHdrLength+header.UDPMinimumSize])

	payload := hdr.Payload()
	data := make([]byte, len(payload))
	copy(data, payload)

	go t.handler.NewPacket(source, destination, data, func(bytes []byte, addr *v2rayNet.UDPAddr) (int, error) {
		var newSourceAddress tcpip.Address
		var newSourcePort uint16

		if addr != nil {
			newSourceAddress = tcpip.AddrFromSlice(addr.IP)
			newSourcePort = uint16(addr.Port)
		} else {
			newSourceAddress = destinationAddress
			newSourcePort = destinationPort
		}

		newIpHdr := header.IPv6(newHeader)
		newIpHdr.SetSourceAddress(newSourceAddress)
		newIpHdr.SetPayloadLength(uint16(header.UDPMinimumSize + len(bytes)))

		udpHdr := header.UDP(newHeader[ipHdrLength:])
		udpHdr.SetSourcePort(newSourcePort)
		udpHdr.SetLength(uint16(header.UDPMinimumSize + len(bytes)))
		udpHdr.SetChecksum(0)
		udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(bytes, header.PseudoHeaderChecksum(header.UDPProtocolNumber, newSourceAddress, sourceAddress, uint16(header.UDPMinimumSize+len(bytes))))))

		payload := buffer.MakeWithData(newHeader)
		payload.Append(buffer.NewViewWithData(bytes))

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: payload,
		})
		err := t.writeRawPacket(pkt)
		pkt.DecRef()
		if err != nil {
			return 0, newError(err.String())
		}

		return len(bytes), nil
	})
}
