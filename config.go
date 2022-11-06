package gomitmproxy

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/AdguardTeam/gomitmproxy/mitm"
)

// OnConnectFunc is a declaration of the Config.OnConnect handler.
type OnConnectFunc func(session *Session, proto string, addr string) (conn net.Conn)

// OnRequestFunc is a declaration of the Config.OnRequest handler.
type OnRequestFunc func(session *Session) (req *http.Request, resp *http.Response)

// OnResponseFunc is a declaration of the Config.OnResponse handler.
type OnResponseFunc func(session *Session) (resp *http.Response)

// OnErrorFunc is a declaration of the Config.OnError handler.
type OnErrorFunc func(session *Session, err error)

// Config is the configuration of the Proxy.
type Config struct {
	// ListenAddr is the TCP address the proxy should listen to.
	ListenAddr *net.TCPAddr

	// TLSConfig is a *tls.Config to use for the HTTP over TLS proxy. If not set
	// the proxy will work as a simple plain HTTP proxy.
	TLSConfig *tls.Config

	// Username is the username to be used in the "Proxy-Authorization" header.
	Username string

	// Password is the password to be used in the "Proxy-Authorization" header.
	Password string

	// MITMConfig defines the MITM configuration of the proxy. If it is not set
	// MITM won't be enabled for this proxy instance.
	MITMConfig *mitm.Config

	// MITMExceptions is a list of hostnames for which MITM will be disabled.
	MITMExceptions []string

	// APIHost is a name of the gomitmproxy API hostname. If it is not set, the
	// API won't be exposed via HTTP.
	//
	// Here are the methods exposed:
	//   1. apihost/cert.crt - serves the authority cert if MITMConfig is
	//   configured.
	APIHost string

	// OnConnect is called when the proxy tries to open a new net.Conn. This
	// function allows hijacking the remote connection and replacing it with a
	// different one.
	//
	// 1. When the proxy handles the HTTP CONNECT.
	//    IMPORTANT: In this case we don't actually use the remote connections.
	//    It is only used to check if the remote endpoint is available.
	// 2. When the proxy bypasses data from the client to the remote endpoint.
	//    For instance, it could happen when there's a WebSocket connection.
	OnConnect OnConnectFunc

	// OnRequest is called when the request has been just received, but has not
	// been sent to the remote server.
	//
	// At this stage, it is possible to do the following things:
	//   1. Modify or even replace the request.
	//   2. Supply an HTTP response to be written to the client.
	//
	// Return nil instead of *http.Request or *http.Response to keep the
	// original request / response.
	//
	// Note that even if you supply your own HTTP response here, the OnResponse
	// handler will be called anyway!
	OnRequest OnRequestFunc

	// OnResponse is called when the response has been just received, but has
	// not been sent to the local client. At this stage you can either keep the
	// original response, or you can replace it with a new one.
	OnResponse OnResponseFunc

	// OnError is called if there's an issue with retrieving the response from
	// the remote server.
	OnError OnErrorFunc
}
