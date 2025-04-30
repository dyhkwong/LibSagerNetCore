package libcore

import "github.com/sirupsen/logrus"

var networkType string

func SetNetworkType(newNetworkType string) {
	if newNetworkType != networkType {
		logrus.Debug("updated network type: ", newNetworkType)
		networkType = newNetworkType
	}
}

var ssid string

func SetSSID(newSSID string) {
	if newSSID != ssid {
		logrus.Debug("updated SSID: ", newSSID)
		ssid = newSSID
	}
}
