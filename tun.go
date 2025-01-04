package libcore

import (
	"container/list"
	"context"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/features/dns/localdns"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"libcore/clash/common/pool"
	"libcore/comm"
	"libcore/gvisor"
	"libcore/nat"
	"libcore/tun"
)

var _ tun.Handler = (*Tun2ray)(nil)

type Tun2ray struct {
	dev                 tun.Tun
	router              string
	v2ray               *V2RayInstance
	fakedns             bool
	sniffing            bool
	overrideDestination bool
	debug               bool

	dumpUid      bool
	trafficStats bool
	pcap         bool

	udpTable  sync.Map
	appStats  sync.Map
	lockTable sync.Map

	connectionsLock sync.Mutex
	connections     list.List

	protectCloser io.Closer
}

type TunConfig struct {
	FileDescriptor      int32
	Protect             bool
	Protector           Protector
	MTU                 int32
	V2Ray               *V2RayInstance
	Gateway4            string
	Gateway6            string
	IPv6Mode            int32
	Implementation      int32
	FakeDNS             bool
	Sniffing            bool
	OverrideDestination bool
	Debug               bool
	DumpUID             bool
	TrafficStats        bool
	PCap                bool
	ErrorHandler        ErrorHandler
	LocalResolver       LocalResolver
	ProtectPath         string
}

type ErrorHandler interface {
	HandleError(err string)
}

func NewTun2ray(config *TunConfig) (*Tun2ray, error) {
	if config.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.WarnLevel)
	}
	t := &Tun2ray{
		router:              config.Gateway4,
		v2ray:               config.V2Ray,
		sniffing:            config.Sniffing,
		overrideDestination: config.OverrideDestination,
		fakedns:             config.FakeDNS,
		debug:               config.Debug,
		dumpUid:             config.DumpUID,
		trafficStats:        config.TrafficStats,
	}

	var err error
	switch config.Implementation {
	case comm.TunImplementationGVisor:
		var pcapFile *os.File
		if config.PCap {
			path := time.Now().UTC().String()
			path = externalAssetsPath + "/pcap/" + path + ".pcap"
			err = os.MkdirAll(filepath.Dir(path), 0o755)
			if err != nil {
				return nil, newError("unable to create pcap dir").Base(err)
			}
			pcapFile, err = os.Create(path)
			if err != nil {
				return nil, newError("unable to create pcap file").Base(err)
			}
		}

		t.dev, err = gvisor.New(config.FileDescriptor, config.MTU, t, gvisor.DefaultNIC, config.PCap, pcapFile, math.MaxUint32, config.IPv6Mode)
	case comm.TunImplementationSystem:
		t.dev, err = nat.New(config.FileDescriptor, config.MTU, t, config.IPv6Mode, config.ErrorHandler.HandleError)
	}

	if err != nil {
		return nil, err
	}

	if !config.Protect {
		config.Protector = noopProtectorInstance
	}

	if len(config.ProtectPath) > 0 {
		t.protectCloser = ServerProtect(config.ProtectPath, config.Protector)
	}

	lookupFunc := func(network, host string) ([]net.IP, error) {
		response, err := config.LocalResolver.LookupIP(network, host)
		if err != nil {
			errStr := err.Error()
			if strings.HasPrefix(errStr, "rcode") {
				r, _ := strconv.Atoi(strings.Split(errStr, " ")[1])
				return nil, dns.RCodeError(r)
			}
			return nil, err
		}
		if response == "" {
			return nil, dns.ErrEmptyResponse
		}
		addrs := Filter(strings.Split(response, ","), func(it string) bool {
			return len(strings.TrimSpace(it)) >= 0
		})
		ips := make([]net.IP, len(addrs))
		for i, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip.To4() != nil {
				ip = ip.To4()
			}
			ips[i] = ip
		}
		if len(ips) == 0 {
			return nil, dns.ErrEmptyResponse
		}
		return ips, nil
	}
	internet.UseAlternativeSystemDialer(&protectedDialer{
		protector: config.Protector,
		resolver: func(domain string) ([]net.IP, error) {
			network := "ip"
			switch config.IPv6Mode {
			case comm.IPv6Disable:
				network = "ip4"
			case comm.IPv6Only:
				network = "ip6"
			}
			ips, err := lookupFunc(network, domain)
			if err != nil || len(ips) == 0 || config.IPv6Mode == comm.IPv6Disable || config.IPv6Mode == comm.IPv6Only {
				return ips, err
			}
			ipv4 := make([]net.IP, 0)
			ipv6 := make([]net.IP, 0)
			for _, ip := range ips {
				if ip.To4() != nil {
					ipv4 = append(ipv4, ip.To4())
				} else {
					ipv6 = append(ipv6, ip)
				}
			}
			if config.IPv6Mode == comm.IPv6Prefer {
				return append(ipv6, ipv4...), err
			}
			// config.IPv6Mode == comm.IPv6Enable
			return append(ipv4, ipv6...), err
		},
	})

	if !config.Protect {
		localdns.SetLookupFunc(nil)
		if config.LocalResolver.SupportExchange() {
			localdns.SetRawQueryFunc(nil)
		}
	} else {
		localdns.SetLookupFunc(lookupFunc)
		if config.LocalResolver.SupportExchange() {
			localdns.SetRawQueryFunc(func(b []byte) ([]byte, error) {
				return config.LocalResolver.Exchange(b)
			})
		}
	}

	return t, nil
}

func (t *Tun2ray) Close() {
	internet.UseAlternativeSystemDialer(nil)
	localdns.SetLookupFunc(nil)
	localdns.SetRawQueryFunc(nil)
	comm.CloseIgnore(t.dev)
	t.connectionsLock.Lock()
	for item := t.connections.Front(); item != nil; item = item.Next() {
		common.Close(item.Value)
	}
	t.connectionsLock.Unlock()
	if t.protectCloser != nil {
		_ = t.protectCloser.Close()
	}
}

func (t *Tun2ray) NewConnection(source v2rayNet.Destination, destination v2rayNet.Destination, conn net.Conn) {
	inbound := &session.Inbound{
		Source:      source,
		Tag:         "tun",
		NetworkType: networkType,
		WifiSSID:    wifiSSID,
	}

	isDns := destination.Address.String() == t.router
	if isDns {
		inbound.Tag = "dns-in"
	}

	var uid uint16
	var self bool

	if t.dumpUid || t.trafficStats {
		u, err := dumpUid(source, destination)
		if err == nil {
			uid = uint16(u)
			var info *UidInfo
			self = uid > 0 && int(uid) == os.Getuid()
			if t.debug && !self && uid >= 10000 {
				if err == nil {
					info, _ = uidDumper.GetUidInfo(int32(uid))
				}
				if info == nil {
					logrus.Infof("[TCP] %s ==> %s", source.NetAddr(), destination.NetAddr())
				} else {
					logrus.Infof("[TCP][%s (%d/%s)] %s ==> %s", info.Label, uid, info.PackageName, source.NetAddr(), destination.NetAddr())
				}
			}

			if uid < 10000 {
				uid = 1000
			}

			inbound.Uid = uint32(uid)
		}
	}

	ctx := toContext(context.Background(), t.v2ray.core)
	ctx = session.ContextWithInbound(ctx, inbound)

	if !isDns && (t.sniffing || t.fakedns) {
		req := session.SniffingRequest{
			Enabled:      true,
			MetadataOnly: t.fakedns && !t.sniffing,
			RouteOnly:    !t.overrideDestination,
		}
		if t.fakedns {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "fakedns")
		}
		if t.sniffing {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "http", "tls")
		}
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: req,
		})
	}

	var stats *appStats
	if t.trafficStats && !self && !isDns {
		if iStats, exists := t.appStats.Load(uid); exists {
			stats = iStats.(*appStats)
		} else {
			iCond, loaded := t.lockTable.LoadOrStore(uid, sync.NewCond(&sync.Mutex{}))
			cond := iCond.(*sync.Cond)
			if loaded {
				cond.L.Lock()
				cond.Wait()
				iStats, exists = t.appStats.Load(uid)
				if !exists {
					panic("unexpected sync read failed")
				}
				stats = iStats.(*appStats)
				cond.L.Unlock()
			} else {
				stats = &appStats{}
				t.appStats.Store(uid, stats)
				t.lockTable.Delete(uid)
				cond.Broadcast()
			}
		}
		atomic.AddInt32(&stats.tcpConn, 1)
		atomic.AddUint32(&stats.tcpConnTotal, 1)
		atomic.StoreInt64(&stats.deactivateAt, 0)
		defer func() {
			if atomic.AddInt32(&stats.tcpConn, -1)+atomic.LoadInt32(&stats.udpConn) == 0 {
				atomic.StoreInt64(&stats.deactivateAt, time.Now().Unix())
			}
		}()
		conn = statsConn{conn, &stats.uplink, &stats.downlink}
	}
	t.connectionsLock.Lock()
	element := t.connections.PushBack(conn)
	t.connectionsLock.Unlock()

	inbound.Conn = conn

	link, err := t.v2ray.dispatcher.Dispatch(ctx, destination)
	if err != nil {
		newError("[TCP] dispatch failed: ", err).WriteToLog()
		return
	} else {
		_ = task.Run(ctx, func() error {
			_ = buf.Copy(buf.NewReader(conn), link.Writer)
			return io.EOF
		}, func() error {
			_ = buf.Copy(link.Reader, buf.NewWriter(conn))
			return io.EOF
		})
	}

	comm.CloseIgnore(conn, link.Reader, link.Writer)

	t.connectionsLock.Lock()
	t.connections.Remove(element)
	t.connectionsLock.Unlock()
}

func (t *Tun2ray) NewPacket(source v2rayNet.Destination, destination v2rayNet.Destination, data *buf.Buffer, writeBack func([]byte, *net.UDPAddr) (int, error), closer io.Closer) {
	natKey := source.NetAddr()

	sendTo := func() bool {
		iConn, ok := t.udpTable.Load(natKey)
		if !ok {
			return false
		}
		conn := iConn.(net.PacketConn)
		_, err := conn.WriteTo(data.Bytes(), &net.UDPAddr{
			IP:   destination.Address.IP(),
			Port: int(destination.Port),
		})
		if err != nil {
			_ = conn.Close()
		}
		return true
	}

	var cond *sync.Cond

	if sendTo() {
		comm.CloseIgnore(closer)
		return
	} else {
		iCond, loaded := t.lockTable.LoadOrStore(natKey, sync.NewCond(&sync.Mutex{}))
		cond = iCond.(*sync.Cond)
		if loaded {
			cond.L.Lock()
			cond.Wait()
			sendTo()
			cond.L.Unlock()

			comm.CloseIgnore(closer)
			return
		}
	}

	inbound := &session.Inbound{
		Source:      source,
		Tag:         "tun",
		NetworkType: networkType,
		WifiSSID:    wifiSSID,
	}
	isDns := destination.Address.String() == t.router
	if isDns {
		inbound.Tag = "dns-in"
	}

	var uid uint16
	var self bool

	if t.dumpUid || t.trafficStats {
		u, err := dumpUid(source, destination)
		if err == nil {
			if u > 19999 {
				logrus.Debug("bad connection owner ", u, ", reset to android.")
				u = 1000
			}

			uid = uint16(u)
			var info *UidInfo
			self = uid > 0 && int(uid) == os.Getuid()

			if t.debug && !self && uid >= 1000 {
				if err == nil {
					info, err = uidDumper.GetUidInfo(int32(uid))
					if err != nil {
						uid = 1000
						info, err = uidDumper.GetUidInfo(int32(uid))
					}
				}
				var tag string
				if !isDns {
					tag = "UDP"
				} else {
					tag = "DNS"
				}

				if info == nil {
					logrus.Infof("[%s] %s ==> %s", tag, source.NetAddr(), destination.NetAddr())
				} else {
					logrus.Infof("[%s][%s (%d/%s)] %s ==> %s", tag, info.Label, uid, info.PackageName, source.NetAddr(), destination.NetAddr())
				}
			}

			if uid < 10000 {
				uid = 1000
			}

			inbound.Uid = uint32(uid)
		}

	}

	ctx := toContext(context.Background(), t.v2ray.core)
	ctx = session.ContextWithInbound(ctx, inbound)

	if !isDns && (t.sniffing || t.fakedns) {
		req := session.SniffingRequest{
			Enabled:      true,
			MetadataOnly: t.fakedns && !t.sniffing,
			RouteOnly:    !t.overrideDestination,
		}
		if t.fakedns {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "fakedns")
		}
		if t.sniffing {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "quic")
		}
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: req,
		})
	}

	conn, err := t.v2ray.dialUDP(ctx)
	if err != nil {
		logrus.Errorf("[UDP] dial failed: %s", err.Error())
		return
	}

	var stats *appStats
	if t.trafficStats && !self && !isDns {
		if iStats, exists := t.appStats.Load(uid); exists {
			stats = iStats.(*appStats)
		} else {
			iCond, loaded := t.lockTable.LoadOrStore(uid, sync.NewCond(&sync.Mutex{}))
			cond := iCond.(*sync.Cond)
			if loaded {
				cond.L.Lock()
				cond.Wait()
				iStats, exists = t.appStats.Load(uid)
				if !exists {
					panic("unexpected sync read failed")
				}
				stats = iStats.(*appStats)
				cond.L.Unlock()
			} else {
				stats = &appStats{}
				t.appStats.Store(uid, stats)
				t.lockTable.Delete(uid)
				cond.Broadcast()
			}
		}
		atomic.AddInt32(&stats.udpConn, 1)
		atomic.AddUint32(&stats.udpConnTotal, 1)
		atomic.StoreInt64(&stats.deactivateAt, 0)
		defer func() {
			if atomic.AddInt32(&stats.udpConn, -1)+atomic.LoadInt32(&stats.tcpConn) == 0 {
				atomic.StoreInt64(&stats.deactivateAt, time.Now().Unix())
			}
		}()
		conn = statsPacketConn{conn, &stats.uplink, &stats.downlink}
	}

	t.connectionsLock.Lock()
	element := t.connections.PushBack(conn)
	t.connectionsLock.Unlock()

	t.udpTable.Store(natKey, conn)

	go sendTo()

	t.lockTable.Delete(natKey)
	cond.Broadcast()

	buffer := pool.Get(pool.RelayBufferSize)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			break
		}
		if isDns {
			addr = nil
		}
		if addr, ok := addr.(*net.UDPAddr); ok {
			_, err = writeBack(buffer[:n], addr)
		} else {
			_, err = writeBack(buffer[:n], nil)
		}
		if err != nil {
			break
		}
	}
	// close
	_ = pool.Put(buffer)
	comm.CloseIgnore(conn, closer)
	t.udpTable.Delete(natKey)

	t.connectionsLock.Lock()
	t.connections.Remove(element)
	t.connectionsLock.Unlock()
}
