package libcore

import (
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/sagernet/gomobile/asset"
	"github.com/sirupsen/logrus"
	"github.com/v2fly/v2ray-core/v5/common/platform/filesystem"
)

const (
	mozillaIncludedPem = "mozilla_included.pem"
)

var (
	assetsPrefix       string
	internalAssetsPath string
	externalAssetsPath string
)

var (
	assetsAccess *sync.Mutex
)

type BoolFunc interface {
	Invoke() bool
}

func InitializeV2Ray(internalAssets string, externalAssets string, prefix string, useSystemCerts BoolFunc) error {
	assetsPrefix = prefix
	internalAssetsPath = internalAssets
	externalAssetsPath = externalAssets

	filesystem.NewFileSeeker = func(path string) (io.ReadSeekCloser, error) {
		_, fileName := filepath.Split(path)

		paths := []string{
			externalAssetsPath + fileName,
			internalAssetsPath + fileName,
		}

		var err error

		for _, path = range paths {
			_, err = os.Stat(path)
			if err == nil {
				return os.Open(path)
			}
		}

		file, err := asset.Open(assetsPrefix + fileName)
		if err == nil {
			return file, nil
		}

		for _, path = range paths {
			_, err = os.Stat(path)
			if err == nil {
				return os.Open(path)
			}
			if !os.IsNotExist(err) {
				return nil, err
			}
		}

		return nil, err
	}

	filesystem.NewFileReader = func(path string) (io.ReadCloser, error) {
		return filesystem.NewFileSeeker(path)
	}

	assetsAccess = new(sync.Mutex)
	assetsAccess.Lock()
	go func() {

		defer assetsAccess.Unlock()

		err := extractRootCACertsPem()
		if err != nil {
			logrus.Warn(newError("failed to extract root ca certs from assets").Base(err))
			return
		}

		UpdateSystemRoots(useSystemCerts.Invoke())
	}()

	return nil
}

func extractRootCACertsPem() error {
	path := internalAssetsPath + mozillaIncludedPem
	sumPath := path + ".sha256sum"
	sumInternal, err := asset.Open(mozillaIncludedPem + ".sha256sum")
	if err != nil {
		return newError("open pem version in assets").Base(err)
	}
	defer sumInternal.Close()
	sumBytes, err := io.ReadAll(sumInternal)
	if err != nil {
		return newError("read internal version").Base(err)
	}
	_, pemSha256sumNotExists := os.Stat(sumPath)
	if pemSha256sumNotExists == nil {
		sumExternal, err := os.ReadFile(sumPath)
		if err == nil {
			if string(sumBytes) == string(sumExternal) {
				return nil
			}
		}
	}
	pemFile, err := os.Create(path)
	if err != nil {
		return newError("create pem file").Base(err)
	}
	defer pemFile.Close()
	pem, err := asset.Open(mozillaIncludedPem)
	if err != nil {
		return newError("open pem in assets").Base(err)
	}
	defer pem.Close()
	_, err = io.Copy(pemFile, pem)
	if err != nil {
		return newError("write pem file")
	}
	return os.WriteFile(sumPath, sumBytes, 0o644)
}
