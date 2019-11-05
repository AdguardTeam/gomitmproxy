package gomitmproxy

import (
	"net/http"
	"strings"
)

// Hop-by-hop headers as defined by RFC2616.
//
// http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-14#section-7.1.3.1
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection", // Non-standard, but required for HTTP/2.
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders removes hop-by-hop headers
func removeHopByHopHeaders(header http.Header) {
	// Additional hop-by-hop headers may be specified in `Connection` headers.
	// http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-14#section-9.1
	for _, vs := range header["Connection"] {
		for _, v := range strings.Split(vs, ",") {
			k := http.CanonicalHeaderKey(strings.TrimSpace(v))
			header.Del(k)
		}
	}

	for _, k := range hopByHopHeaders {
		header.Del(k)
	}
}
