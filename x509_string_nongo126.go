//go:build !go1.26

/*
Copyright (C) 2026  dyhkwong

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// modified from https://github.com/golang/go/blob/c6f882f6c58ed56fa4bd2d8256ec55d9992c3583/src/crypto/x509/x509_string.go

package libsagernetcore

import (
	"crypto/x509"
	"strconv"
)

const (
	_KeyUsage_name_0  = "digitalSignaturecontentCommitment"
	_KeyUsage_name_1  = "keyEncipherment"
	_KeyUsage_name_2  = "dataEncipherment"
	_KeyUsage_name_3  = "keyAgreement"
	_KeyUsage_name_4  = "keyCertSign"
	_KeyUsage_name_5  = "cRLSign"
	_KeyUsage_name_6  = "encipherOnly"
	_KeyUsage_name_7  = "decipherOnly"
	_ExtKeyUsage_name = "anyExtendedKeyUsageserverAuthclientAuthcodeSigningemailProtectionipsecEndSystemipsecTunnelipsecUsertimeStampingOCSPSigningmsSGCnsSGCmsCodeCommsKernelCode"
)

var (
	_KeyUsage_index_0  = [...]uint8{0, 16, 33}
	_ExtKeyUsage_index = [...]uint8{0, 19, 29, 39, 50, 65, 79, 90, 99, 111, 122, 127, 132, 141, 153}
)

func keyUsageToString(i x509.KeyUsage) string {
	switch {
	case 1 <= i && i <= 2:
		i -= 1
		return _KeyUsage_name_0[_KeyUsage_index_0[i]:_KeyUsage_index_0[i+1]]
	case i == 4:
		return _KeyUsage_name_1
	case i == 8:
		return _KeyUsage_name_2
	case i == 16:
		return _KeyUsage_name_3
	case i == 32:
		return _KeyUsage_name_4
	case i == 64:
		return _KeyUsage_name_5
	case i == 128:
		return _KeyUsage_name_6
	case i == 256:
		return _KeyUsage_name_7
	default:
		return "KeyUsage(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}

func extKeyUsageToString(i x509.ExtKeyUsage) string {
	idx := int(i) - 0
	if i < 0 || idx >= len(_ExtKeyUsage_index)-1 {
		return "ExtKeyUsage(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _ExtKeyUsage_name[_ExtKeyUsage_index[idx]:_ExtKeyUsage_index[idx+1]]
}
