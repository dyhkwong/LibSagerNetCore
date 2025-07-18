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

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/bytespool"
	"github.com/v2fly/v2ray-core/v5/common/log"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"libcore/comm"
	"libcore/gvisor"
	"libcore/nat"
	"libcore/tun"
)

var _ tun.Handler = (*Tun2ray)(nil)

type Tun2ray struct {
	dev                 tun.Tun
	mtu                 int32
	router              string
	v2ray               *V2RayInstance
	fakedns             bool
	sniffing            bool
	overrideDestination bool

	dumpUID      bool
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
	EnableIPv6          bool
	Implementation      int32
	FakeDNS             bool
	Sniffing            bool
	OverrideDestination bool
	Debug               bool
	DumpUID             bool
	TrafficStats        bool
	PCap                bool
	ProtectPath         string
}

func NewTun2ray(config *TunConfig) (*Tun2ray, error) {
	t := &Tun2ray{
		mtu:                 config.MTU,
		router:              config.Gateway4,
		v2ray:               config.V2Ray,
		sniffing:            config.Sniffing,
		overrideDestination: config.OverrideDestination,
		fakedns:             config.FakeDNS,
		dumpUID:             config.DumpUID,
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

		t.dev, err = gvisor.New(config.FileDescriptor, config.MTU, t, gvisor.DefaultNIC, config.PCap, pcapFile, math.MaxUint32, config.EnableIPv6)
	case comm.TunImplementationSystem:
		t.dev, err = nat.New(config.FileDescriptor, config.MTU, t, config.EnableIPv6)
	}

	if err != nil {
		return nil, err
	}

	if !config.Protect {
		config.Protector = &noopProtector{}
	}

	if len(config.ProtectPath) > 0 {
		t.protectCloser = ServerProtect(config.ProtectPath, config.Protector)
	}

	lookupFunc := func(network, host string) ([]net.IP, error) {
		response, err := config.V2Ray.LocalResolver.LookupIP(network, host)
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
			network := "ip4"
			if config.EnableIPv6 {
				network = "ip"
			}
			return lookupFunc(network, domain)
		},
	})

	return t, nil
}

func (t *Tun2ray) Close() {
	internet.UseAlternativeSystemDialer(nil)
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
		SSID:        ssid,
	}

	isDns := destination.Address.String() == t.router
	if isDns {
		if destination.Port != 53 {
			t.connectionsLock.Lock()
			_ = t.connections.PushBack(conn)
			t.connectionsLock.Unlock()
			return
		}
		inbound.Tag = "dns-in"
	}

	var uid uint16
	var self bool

	if t.dumpUID || t.trafficStats {
		u, err := dumpUID(source, destination)
		if err == nil {
			uid = uint16(u)
			self = int(uid) == os.Getuid()
			if !self {
				info, _ := uidDumper.GetUIDInfo(int32(uid))
				if info == nil {
					newError("[TCP] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog()
				} else {
					newError("[TCP][", info.Label, " (", uid, "/", info.PackageName, ")] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog()
				}
			}
			inbound.UID = uint32(uid)
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
		conn = &statsConn{conn, &stats.uplink, &stats.downlink}
	}
	t.connectionsLock.Lock()
	element := t.connections.PushBack(conn)
	t.connectionsLock.Unlock()

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   source,
		To:     destination,
		Status: log.AccessAccepted,
	})

	proxyConn, err := t.v2ray.dial(ctx, destination)
	if err != nil {
		newError("[TCP] dial failed: ", err).WriteToLog()
		comm.CloseIgnore(conn)
		return
	}
	_ = task.Run(ctx, func() error {
		_ = buf.Copy(buf.NewReader(conn), buf.NewWriter(proxyConn))
		return io.EOF
	}, func() error {
		_ = buf.Copy(buf.NewReader(proxyConn), buf.NewWriter(conn))
		return io.EOF
	})
	comm.CloseIgnore(conn, proxyConn)

	t.connectionsLock.Lock()
	t.connections.Remove(element)
	t.connectionsLock.Unlock()
}

func (t *Tun2ray) NewPacket(source v2rayNet.Destination, destination v2rayNet.Destination, data []byte, writeBack func([]byte, *net.UDPAddr) (int, error)) {
	natKey := source.NetAddr()

	sendTo := func() bool {
		iConn, ok := t.udpTable.Load(natKey)
		if !ok {
			return false
		}
		conn := iConn.(net.PacketConn)
		_, err := conn.WriteTo(data, &net.UDPAddr{
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
		return
	} else {
		iCond, loaded := t.lockTable.LoadOrStore(natKey, sync.NewCond(&sync.Mutex{}))
		cond = iCond.(*sync.Cond)
		if loaded {
			cond.L.Lock()
			cond.Wait()
			sendTo()
			cond.L.Unlock()
			return
		}
	}

	inbound := &session.Inbound{
		Source:      source,
		Tag:         "tun",
		NetworkType: networkType,
		SSID:        ssid,
	}
	isDns := destination.Address.String() == t.router
	if isDns {
		if destination.Port != 53 {
			return
		}
		inbound.Tag = "dns-in"
	}

	var uid uint16
	var self bool

	if t.dumpUID || t.trafficStats {
		u, err := dumpUID(source, destination)
		if err == nil {
			uid = uint16(u)
			self = int(uid) == os.Getuid()
			if !self {
				info, _ := uidDumper.GetUIDInfo(int32(uid))
				var tag string
				if !isDns {
					tag = "UDP"
				} else {
					tag = "DNS"
				}
				if info == nil {
					newError("[", tag, "] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog()
				} else {
					newError("[", tag, "][", info.Label, " (", uid, "/", info.PackageName, ")] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog()
				}
			}
			inbound.UID = uint32(uid)
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

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   source,
		To:     destination,
		Status: log.AccessAccepted,
	})

	conn, err := t.v2ray.dialUDP(ctx)
	if err != nil {
		newError("[UDP] dial failed").Base(err).AtError().WriteToLog()
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
		conn = &statsPacketConn{conn, &stats.uplink, &stats.downlink}
	}

	t.connectionsLock.Lock()
	element := t.connections.PushBack(conn)
	t.connectionsLock.Unlock()

	t.udpTable.Store(natKey, conn)

	go sendTo()

	t.lockTable.Delete(natKey)
	cond.Broadcast()

	buffer := bytespool.Alloc(t.mtu)
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
	bytespool.Free(buffer)
	comm.CloseIgnore(conn)
	t.udpTable.Delete(natKey)

	t.connectionsLock.Lock()
	t.connections.Remove(element)
	t.connectionsLock.Unlock()
}
