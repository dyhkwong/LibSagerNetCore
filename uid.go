package libcore

import (
	"syscall"

	"github.com/v2fly/v2ray-core/v5/common/net"
)

var (
	uidDumper UIDDumper
	useProcfs bool
)

type UIDInfo struct {
	PackageName string
	Label       string
}

type UIDDumper interface {
	DumpUID(ipProto int32, srcIp string, srcPort int32, destIp string, destPort int32) (int32, error)
	GetUIDInfo(uid int32) (*UIDInfo, error)
}

func SetUIDDumper(dumper UIDDumper, procfs bool) {
	uidDumper = dumper
	useProcfs = procfs
}

func dumpUID(source net.Destination, destination net.Destination) (int32, error) {
	if useProcfs {
		return querySocketUidFromProcFs(source, destination), nil
	} else {
		var ipProto int32
		if destination.Network == net.Network_TCP {
			ipProto = syscall.IPPROTO_TCP
		} else {
			ipProto = syscall.IPPROTO_UDP
		}
		return uidDumper.DumpUID(ipProto, source.Address.IP().String(), int32(source.Port), destination.Address.IP().String(), int32(destination.Port))
	}
}
