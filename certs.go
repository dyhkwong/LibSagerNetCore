package libcore

import (
	"crypto/x509"
	"os"
	_ "unsafe"

	"github.com/sirupsen/logrus"
)

//go:linkname systemRoots crypto/x509.systemRoots
var systemRoots *x509.CertPool

func updateRootCACerts() {
	x509.SystemCertPool()
	roots := x509.NewCertPool()
	var pemPath string
	if f, err := os.Stat(externalAssetsPath + mozillaIncludedPem); err == nil && !f.IsDir() {
		pemPath = externalAssetsPath + mozillaIncludedPem
		logrus.Warn("loading root ca certificates from external assets dir")
	} else {
		pemPath = internalAssetsPath + mozillaIncludedPem
		logrus.Warn("loading root ca certificates from internal assets dir")
	}
	pemFile, err := os.ReadFile(pemPath)
	if err != nil {
		logrus.Warn("failed to load root ca certificates: ", err)
		return
	}
	if !roots.AppendCertsFromPEM(pemFile) {
		logrus.Warn("failed to append certificates from pem")
		return
	}
	systemRoots = roots
	logrus.Info("updated root ca certificate list")
}

var disableSystem bool

func UpdateSystemRoots(useSystem bool) {
	if disableSystem != useSystem {
		return
	}
	disableSystem = !disableSystem

	if useSystem {
		systemRoots, _ = x509.SystemCertPool()
		logrus.Info("reset systemRoots")
	} else {
		updateRootCACerts()
	}
}
