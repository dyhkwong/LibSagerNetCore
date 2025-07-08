package libcore

var networkType string

func SetNetworkType(newNetworkType string) {
	if newNetworkType != networkType {
		newError("updated network type: ", newNetworkType).AtDebug().WriteToLog()
		networkType = newNetworkType
	}
}

var ssid string

func SetSSID(newSSID string) {
	if newSSID != ssid {
		newError("updated SSID: ", newSSID).AtDebug().WriteToLog()
		ssid = newSSID
	}
}
