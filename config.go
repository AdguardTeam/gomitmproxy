package gomitmproxy

import (
	"crypto/tls"
	"net"

	"github.com/ameshkov/gomitmproxy/mitm"
)

// Config is the configuration of the Proxy
type Config struct {
	ListenAddr *net.TCPAddr // Address to listen to

	// TLSConfig is a config to use for the HTTP over TLS proxy
	// If not set, gomitmproxy will work as a simple plain HTTP proxy
	TLSConfig *tls.Config

	MITMConfig     *mitm.Config // If not nil, MITM is enabled for the proxy
	MITMExceptions []string     // A list of hostnames for which MITM will be disabled
}
