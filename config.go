package gomitmproxy

import (
	"net"

	"github.com/ameshkov/gomitmproxy/mitm"
)

// Config is the configuration of the Proxy
type Config struct {
	ListenAddr *net.TCPAddr // Address to listen to

	MITMConfig     *mitm.Config // If not nil, MITM is enabled for the proxy
	MITMExceptions []string     // A list of hostnames for which MITM will be disabled
}
