package libcore

import (
	"os"

	"libcore/stun"
)

//go:generate go run ./errorgen

func Setenv(key, value string) error {
	return os.Setenv(key, value)
}

func Unsetenv(key string) error {
	return os.Unsetenv(key)
}

func IcmpPing(address string, timeout int32) (int32, error) {
	return icmpPing(address, timeout)
}

type StunResult struct {
	NatMapping   string
	NatFiltering string
	Error        string
}

func StunTest(serverAddress string, useSOCKS5 bool, socksPort int32, dnsPort int32) *StunResult {
	result := new(StunResult)
	natBehavior, err := stun.Test(serverAddress, useSOCKS5, int(socksPort), int(dnsPort))
	if err != nil {
		result.Error = err.Error()
	}
	if natBehavior != nil {
		result.NatMapping = natBehavior.MappingType.String()
		result.NatFiltering = natBehavior.FilteringType.String()
	}
	return result
}

type StunLegacyResult struct {
	NatType string
	Host    string
	Error   string
}

func StunLegacyTest(serverAddress string, useSOCKS5 bool, socksPort int32, dnsPort int32) *StunLegacyResult {
	result := new(StunLegacyResult)
	natType, host, err := stun.TestLegacy(serverAddress, useSOCKS5, int(socksPort), int(dnsPort))
	if err != nil {
		result.Error = err.Error()
	}
	if host != nil {
		result.Host = host.String()
	}
	if natType > 0 {
		result.NatType = natType.String()
	}
	return result
}
