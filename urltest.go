package libcore

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
)

func UrlTest(instance *V2RayInstance, inbound string, link string, timeout int32) (int32, error) {
	transport := &http.Transport{
		TLSHandshakeTimeout: time.Duration(timeout) * time.Millisecond,
		DisableKeepAlives:   true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
			if err != nil {
				return nil, err
			}
			if inbound != "" {
				ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: inbound})
			}
			return instance.dial(ctx, dest)
		},
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequest("GET", link, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected response status: %d", resp.StatusCode)
	}
	return int32(time.Since(start).Milliseconds()), nil
}
