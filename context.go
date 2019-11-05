package gomitmproxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
)

var (
	// auto-incremented value, used for every new Context instance
	currentContextID = int64(100000)
)

// Context contains all the necessary information about the connection
// that is currently processing by the proxy
type Context struct {
	id            int64 // connection id
	lastChildID   int64 // last child context ID (auto-incremented value)
	lastSessionID int64 // last session ID (auto-incremented value)

	// parent context makes sense in the case of handling HTTP CONNECT tunnels
	// also, it may become useful in the future when HTTP/2 support is added
	parent *Context

	conn    net.Conn          // network connection
	localRW *bufio.ReadWriter // buffered read/writer to this connection
}

// Session contains all the necessary information about
// the request-response pair that is currently being processed
type Session struct {
	id int64 // session ID

	ctx *Context       // connection context
	req *http.Request  // http request
	res *http.Response // http response
}

// newContext creates a new Context instance
func newContext(conn net.Conn, localRW *bufio.ReadWriter, parent *Context) *Context {
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
	}
}

// newSession creates a new Session instance
func newSession(ctx *Context, req *http.Request) *Session {
	sessionID := atomic.AddInt64(&ctx.lastSessionID, 1)
	return &Session{
		id:  sessionID,
		ctx: ctx,
		req: req,
	}
}

// ID -- context unique ID
func (c *Context) ID() string {
	if c.parent != nil {
		return fmt.Sprintf("%d-%d", c.parent.id, c.id)
	}
	return fmt.Sprintf("%d", c.id)
}

// ID -- session unique ID
func (s *Session) ID() string {
	return fmt.Sprintf("%s-%d", s.ctx.ID(), s.id)
}
