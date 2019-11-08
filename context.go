package gomitmproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

var (
	// auto-incremented value, used for every new Context instance
	currentContextID = int64(100000)
)

// Context contains all the necessary information about the connection
// that is currently processing by the proxy
type Context struct {
	id            int64 // connection id
	lastSessionID int64 // last session ID (auto-incremented value)

	// parent session makes sense in the case of handling HTTP CONNECT tunnels
	// also, it may become useful in the future when HTTP/2 support is added
	parent *Session

	conn    net.Conn          // network connection
	localRW *bufio.ReadWriter // buffered read/writer to this connection

	// props is a map with custom properties that can be used
	// by gomitmproxy to store context properties
	props map[string]interface{}
}

// Session contains all the necessary information about
// the request-response pair that is currently being processed
type Session struct {
	id          int64 // session ID
	lastChildID int64 // last child context ID (auto-incremented value)

	ctx *Context       // connection context
	req *http.Request  // http request
	res *http.Response // http response

	// props is a map with custom properties that can be used
	// by gomitmproxy to store session properties
	props map[string]interface{}
}

// newContext creates a new Context instance
func newContext(conn net.Conn, localRW *bufio.ReadWriter, parent *Session) *Context {
	var contextID int64
	if parent == nil {
		contextID = atomic.AddInt64(&currentContextID, 1)
	} else {
		contextID = atomic.AddInt64(&parent.lastChildID, 1)
	}

	return &Context{
		id:      contextID,
		parent:  parent,
		conn:    conn,
		localRW: localRW,
		props:   map[string]interface{}{},
	}
}

// newSession creates a new Session instance
func newSession(ctx *Context, req *http.Request) *Session {
	sessionID := atomic.AddInt64(&ctx.lastSessionID, 1)
	return &Session{
		id:    sessionID,
		ctx:   ctx,
		req:   req,
		props: map[string]interface{}{},
	}
}

// ID -- context unique ID
func (c *Context) ID() string {
	if c.parent != nil {
		return fmt.Sprintf("%s-%d", c.parent.ID(), c.id)
	}
	return fmt.Sprintf("%d", c.id)
}

// IsMITM returns true if this context is for a MITM'ed connection
func (c *Context) IsMITM() bool {
	if _, ok := c.conn.(*tls.Conn); c.parent != nil && ok {
		return true
	}

	return false
}

// SetDeadline sets the read and write deadlines associated
// with the connection. See net.Conn.SetDeadline for more details.
//
// The difference is that our contexts can be nested, so we
// search for the topmost parent context recursively and
// call SetDeadline for its connection only as this is the
// real underlying network connection.
func (c *Context) SetDeadline(t time.Time) error {
	if c.parent == nil {
		return c.conn.SetDeadline(t)
	}
	return c.parent.ctx.SetDeadline(t)
}

// GetProp gets context property (previously saved using SetProp)
func (c *Context) GetProp(key string) (interface{}, bool) {
	v, ok := c.props[key]
	return v, ok
}

// SetProp sets the context property
func (c *Context) SetProp(key string, val interface{}) {
	c.props[key] = val
}

// ID -- session unique ID
func (s *Session) ID() string {
	return fmt.Sprintf("%s-%d", s.ctx.ID(), s.id)
}

// Request returns the HTTP request of this session
func (s *Session) Request() *http.Request {
	return s.req
}

// Response returns the HTTP response of this session
func (s *Session) Response() *http.Response {
	return s.res
}

// Ctx returns this session's context
func (s *Session) Ctx() *Context {
	return s.ctx
}

// GetProp gets session property (previously saved using SetProp)
func (s *Session) GetProp(key string) (interface{}, bool) {
	v, ok := s.props[key]
	return v, ok
}

// SetProp sets the session property
func (s *Session) SetProp(key string, val interface{}) {
	s.props[key] = val
}

// RemoteAddr returns this session's remote address
func (s *Session) RemoteAddr() string {
	if s.ctx.IsMITM() {
		return s.ctx.parent.RemoteAddr()
	}

	host := s.req.URL.Host
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}

	if s.req.URL.Scheme == "https" {
		return fmt.Sprintf("%s:443", host)
	}

	return fmt.Sprintf("%s:80", host)
}
