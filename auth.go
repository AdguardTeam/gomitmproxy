package gomitmproxy

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/AdguardTeam/gomitmproxy/proxyutil"
)

// See 2 (end of page 4) https://www.ietf.org/rfc/rfc2617.txt
// "To receive authorization, the client sends the userid and password,
// separated by a single colon (":") character, within a base64
// encoded string in the credentials."
// It is not meant to be urlencoded.
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// newNotAuthorizedResponse creates a new "407 (Proxy Authentication Required)" response
func newNotAuthorizedResponse(session *Session) *http.Response {
	res := proxyutil.NewResponse(http.StatusProxyAuthRequired, nil, session.req)

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authenticate
	res.Header.Set("Proxy-Authenticate", "Basic")
	return res
}

// authorize checks Proxy-Authorization header
// returns true if request is authorized
// if it returns false, it also returns a response to write to the client
func (p *Proxy) authorize(session *Session) (bool, *http.Response) {
	if session.ctx.parent != nil {
		// If we're here, it means the connection is authorized already
		return true, nil
	}

	if p.Username == "" {
		return true, nil
	}

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization
	proxyAuth := session.req.Header.Get("Proxy-Authorization")
	if strings.Index(proxyAuth, "Basic ") != 0 {
		return false, newNotAuthorizedResponse(session)
	}

	authHeader := proxyAuth[len("Basic "):]
	if authHeader != basicAuth(p.Username, p.Password) {
		return false, newNotAuthorizedResponse(session)
	}

	return true, nil
}
