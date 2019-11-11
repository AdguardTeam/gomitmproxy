package gomitmproxy

import (
	"errors"
	"io"
	"net"
)

var errShutdown = errors.New("proxy is shutting down")
var errClose = errors.New("closing connection")

// isCloseable checks if the error signals about connection being closed
// or the proxy shutting down
func isCloseable(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	switch err {
	case io.EOF, io.ErrClosedPipe, errClose, errShutdown:
		return true
	}

	return false
}

// A peekedConn subverts the net.Conn.Read implementation, primarily so that
// sniffed bytes can be transparently prepended.
type peekedConn struct {
	net.Conn
	r io.Reader
}

// Read allows control over the embedded net.Conn's read data. By using an
// io.MultiReader one can read from a conn, and then replace what they read, to
// be read again.
func (c *peekedConn) Read(buf []byte) (int, error) { return c.r.Read(buf) }
