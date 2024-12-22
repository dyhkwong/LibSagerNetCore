package libcore

import (
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/proxy/sip003"
	"github.com/v2fly/v2ray-core/v5/proxy/sip003/self"

	"libcore/clash/transport/simple-obfs"
)

var (
	_ sip003.Plugin       = (*obfsLocalPlugin)(nil)
	_ sip003.StreamPlugin = (*obfsLocalPlugin)(nil)
)

func init() {
	sip003.RegisterPlugin("obfs-local", func() sip003.Plugin {
		return new(obfsLocalPlugin)
	})
}

type obfsLocalPlugin struct {
	tls  bool
	host string
	port string
}

func (p *obfsLocalPlugin) Init(_, _, _, _, _ string, _ []string) error {
	panic("Please call InitStreamPlugin.")
}

func (p *obfsLocalPlugin) InitStreamPlugin(remotePort string, pluginOpts string) error {
	options, err := self.ParsePluginOptions(pluginOpts)
	if err != nil {
		return newError("obfs-local: failed to parse plugin options").Base(err)
	}

	mode := "http"

	if s, ok := options.Get("obfs"); ok {
		mode = s
	}

	if s, ok := options.Get("obfs-host"); ok {
		p.host = s
	}

	switch mode {
	case "http":
	case "tls":
		p.tls = true
	default:
		return newError("unknown obfs mode ", mode)
	}

	p.port = remotePort

	return nil
}

func (p *obfsLocalPlugin) StreamConn(conn net.Conn) net.Conn {
	if !p.tls {
		return obfs.NewHTTPObfs(conn, p.host, p.port)
	} else {
		return obfs.NewTLSObfs(conn, p.host)
	}
}

func (p *obfsLocalPlugin) Close() error {
	return nil
}
