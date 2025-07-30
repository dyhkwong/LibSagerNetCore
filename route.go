package libcore

import (
	"github.com/v2fly/v2ray-core/v5/app/proxyman/inbound"
)

type UidDumper inbound.UidDumper

func SetUidDumper(uidDumper UidDumper, useProcfs bool) {
	inbound.SetUidDumper(uidDumper, useProcfs)
}

func SetNetworkType(newNetworkType string) {
	if inbound.GetNetworkType() != newNetworkType {
		inbound.SetNetworkType(newNetworkType)
	}
}

func SetSSID(newSSID string) {
	if inbound.GetSSID() != newSSID {
		inbound.SetSSID(newSSID)
	}
}
