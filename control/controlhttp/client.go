// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package controlhttp implements the Tailscale 2021 control protocol
// base transport over HTTP.
//
// This tunnels the protocol in control/controlbase over HTTP with a
// variety of compatibility fallbacks for handling picky or deep
// inspecting proxies.
//
// In the happy path, a client makes a single cleartext HTTP request
// to the server, the server responds with 101 Switching Protocols,
// and the control base protocol takes place over plain TCP.
//
// In the compatibility path, the client does the above over HTTPS,
// resulting in double encryption (once for the control transport, and
// once for the outer TLS layer).
package controlhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"

	"tailscale.com/control/controlbase"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netns"
	"tailscale.com/net/tlsdial"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/types/key"
)

// upgradeHeader is the value of the Upgrade HTTP header used to
// indicate the Tailscale control protocol.
const upgradeHeader = "tailscale-control-protocol"

// Dial connects to the HTTP server at addr, requests to switch to the
// Tailscale control protocol, and returns an established control
// protocol connection.
//
// If Dial fails to connect using addr, it also tries to tunnel over
// TLS to <addr's host>:443 as a compatibility fallback.
func Dial(ctx context.Context, addr string, machineKey key.MachinePrivate, controlKey key.MachinePublic) (*controlbase.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	a := attempt{
		ctx:        ctx,
		host:       host,
		httpPort:   port,
		httpsPort:  "443",
		machineKey: machineKey,
		controlKey: controlKey,
		proxyFunc:  tshttpproxy.ProxyFromEnvironment,
	}
	return a.dial()
}

type attempt struct {
	ctx        context.Context
	host       string
	httpPort   string
	httpsPort  string
	machineKey key.MachinePrivate
	controlKey key.MachinePublic
	proxyFunc  func(*http.Request) (*url.URL, error)

	// For tests only
	insecureTLS bool
}

func (a *attempt) dial() (*controlbase.Conn, error) {
	u := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(a.host, a.httpPort),
		Path:   "/switch",
	}
	conn, httpErr := a.tryURL(u)
	if httpErr == nil {
		return controlbase.Client(a.ctx, conn, a.machineKey, a.controlKey)
	}

	// Connecting over plain HTTP failed, assume it's an HTTP proxy
	// being difficult and see if we can get through over HTTPS.
	u.Scheme = "https"
	u.Host = net.JoinHostPort(a.host, a.httpsPort)
	conn, tlsErr := a.tryURL(u)
	if tlsErr == nil {
		return controlbase.Client(a.ctx, conn, a.machineKey, a.controlKey)
	}

	return nil, fmt.Errorf("all connection attempts failed (HTTP: %v, HTTPS: %v)", httpErr, tlsErr)
}

func (a *attempt) tryURL(u *url.URL) (net.Conn, error) {
	dns := &dnscache.Resolver{
		Forward:          dnscache.Get().Forward,
		LookupIPFallback: dnsfallback.Lookup,
		UseLastGood:      true,
	}
	dialer := netns.NewDialer(log.Printf)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = a.proxyFunc
	tshttpproxy.SetTransportGetProxyConnectHeader(tr)
	tr.DialContext = dnscache.Dialer(dialer.DialContext, dns)
	// Disable HTTP2, since h2 can't do protocol switching.
	tr.TLSClientConfig.NextProtos = []string{}
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	tr.TLSClientConfig = tlsdial.Config(a.host, tr.TLSClientConfig)
	if a.insecureTLS {
		tr.TLSClientConfig.InsecureSkipVerify = true
		tr.TLSClientConfig.VerifyConnection = nil
	}
	tr.DialTLSContext = dnscache.TLSDialer(dialer.DialContext, dns, tr.TLSClientConfig)
	tr.DisableCompression = true

	// (mis)use httptrace to extract the underlying net.Conn from the
	// transport. We make exactly 1 request using this transport, so
	// there will be exactly 1 GotConn call. Additionally, the
	// transport handles 101 Switching Protocols correctly, such that
	// the Conn will not be reused or kept alive by the transport once
	// the response has been handed back from RoundTrip.
	//
	// Technically, the underlying net.Conn is wrapped in a
	// bufio.Reader within Transport, but the way the control protocol
	// works, the client is the first to transmit after the protocol
	// switch. This means the buffer within the Transport will never
	// contain more than just the HTTP response, and as a result it's
	// safe to steal the raw net.Conn and use that.
	var switchedConn net.Conn
	trace := httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			switchedConn = info.Conn
		},
	}
	ctx := httptrace.WithClientTrace(a.ctx, &trace)

	req := &http.Request{
		Method: "POST",
		URL:    u,
		Header: http.Header{
			"Upgrade":    []string{upgradeHeader},
			"Connection": []string{"upgrade"},
		},
	}
	req = req.WithContext(ctx)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("unexpected HTTP response: %s", resp.Status)
	}

	// From here we've confirmed the response is a protocol switch, so
	// the switchedConn will no longer be touched by Transport. It's
	// safe for us to handle, and also our responsibility to close on
	// error.

	if switchedConn == nil {
		return nil, fmt.Errorf("httptrace didn't provide a connection")
	}

	if next := resp.Header.Get("Upgrade"); next != "tailscale-control-protocol" {
		switchedConn.Close()
		return nil, fmt.Errorf("server switched to unexpected protocol %q", next)
	}

	return switchedConn, nil
}
