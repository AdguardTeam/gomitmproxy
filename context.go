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
	// currentContextID is an auto-incremented value, used for every new
	// Context instance.
	currentContextID = int64(100000)
)

// Context contains all the necessary information about the connection that is
// currently being processed by the proxy.
type Context struct {
	// id is the connection identifier.
	id int64

	// lastSessionID is the number of the last session processed via the
	// connection. This is an auto-incremented field.
	lastSessionID int64

	// parent session makes sense in the case of handling HTTP CONNECT tunnels.
	// Also, it may become useful in the future when HTTP/2 support is added.
	parent *Session

	// conn is the local network connection.
	conn net.Conn

	// localRW is a buffered read/writer to conn.
	localRW *bufio.ReadWriter

	// props is a map with custom properties that can be used by gomitmproxy to
	// store additional context properties.
	props map[string]interface{}
}

// newContext creates a new Context instance.
func newContext(conn net.Conn, localRW *bufio.ReadWriter, parent *Session) (ctx *Context) {
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

// ID is the context's unique ID.
func (c *Context) ID() (id string) {
	if c.parent != nil {
		return fmt.Sprintf("%s-%d", c.parent.ID(), c.id)
	}

	return fmt.Sprintf("%d", c.id)
}

// IsMITM returns true if this context is for a MITMed connection.
func (c *Context) IsMITM() (ok bool) {
	if _, ok = c.conn.(*tls.Conn); c.parent != nil && ok {
		return true
	}

	return false
}

// SetDeadline sets the read and write deadlines associated with the connection.
//
// The difference is that our contexts can be nested, so we search for the
// topmost parent context recursively and call SetDeadline for its connection
// only as this is the real underlying network connection.
func (c *Context) SetDeadline(t time.Time) (err error) {
	if c.parent == nil {
		return c.conn.SetDeadline(t)
	}

	return c.parent.ctx.SetDeadline(t)
}

// GetProp gets context property (previously saved using SetProp).
func (c *Context) GetProp(key string) (v interface{}, ok bool) {
	v, ok = c.props[key]

	return v, ok
}

// SetProp sets the context's property.
func (c *Context) SetProp(key string, val interface{}) {
	c.props[key] = val
}

// Session contains all the necessary information about the request-response
// pair that is currently being processed.
type Session struct {
	// id is a session identifier.
	id int64
	// lastChildID is the last child context's identifier. This field is
	// automatically incremented.
	lastChildID int64

	// ctx is a context of the connection this session belongs to.
	ctx *Context

	// req is the *http.Request that's being processed in this session.
	req *http.Request

	// res is the *http.Response that's being processed in this session.
	res *http.Response

	// props is a map with custom properties that can be used by gomitmproxy to
	// store additional session properties.
	props map[string]interface{}
}

// newSession creates a new Session instance.
func newSession(ctx *Context, req *http.Request) (sess *Session) {
	sessionID := atomic.AddInt64(&ctx.lastSessionID, 1)

	return &Session{
		id:    sessionID,
		ctx:   ctx,
		req:   req,
		props: map[string]interface{}{},
	}
}

// ID returns a unique session identifier.
func (s *Session) ID() (id string) {
	return fmt.Sprintf("%s-%d", s.ctx.ID(), s.id)
}

// Request returns the HTTP request of this session.
func (s *Session) Request() (req *http.Request) {
	return s.req
}

// Response returns the HTTP response of this session.
func (s *Session) Response() (resp *http.Response) {
	return s.res
}

// Ctx returns this session's context.
func (s *Session) Ctx() (ctx *Context) {
	return s.ctx
}

// GetProp gets session property (previously saved using SetProp).
func (s *Session) GetProp(key string) (v interface{}, ok bool) {
	v, ok = s.props[key]

	return v, ok
}

// SetProp sets a session's property.
func (s *Session) SetProp(key string, val interface{}) {
	s.props[key] = val
}

// RemoteAddr returns this session's remote address.
func (s *Session) RemoteAddr() (addr string) {
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
