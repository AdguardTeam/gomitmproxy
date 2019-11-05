package gomitmproxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/AdguardTeam/golibs/log"
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

// newResponse builds a new HTTP response.
// If body is nil, an empty byte.Buffer will be provided to be consistent with
// the guarantees provided by http.Transport and http.Client.
func newResponse(code int, body io.Reader, req *http.Request) *http.Response {
	if body == nil {
		body = &bytes.Buffer{}
	}

	rc, ok := body.(io.ReadCloser)
	if !ok {
		rc = ioutil.NopCloser(body)
	}

	res := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       rc,
		Request:    req,
	}

	if req != nil {
		res.Close = req.Close
		res.Proto = req.Proto
		res.ProtoMajor = req.ProtoMajor
		res.ProtoMinor = req.ProtoMinor
	}

	return res
}

// newErrorResponse creates a new HTTP response with status code 502 Bad Gateway
// "Warning" header is populated with the error details
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Warning
func newErrorResponse(req *http.Request, err error) *http.Response {
	res := newResponse(http.StatusBadGateway, nil, req)
	res.Close = true

	date := res.Header.Get("Date")
	if date == "" {
		date = time.Now().Format(http.TimeFormat)
	}

	w := fmt.Sprintf(`199 "gomitmproxy" %q %q`, err.Error(), date)
	res.Header.Add("Warning", w)
	return res
}

func writeResponse(session *Session) error {
	var err error
	if err = session.res.Write(session.ctx.localRW); err != nil {
		log.Error("id=%s: got error while writing response back to client: %v", session.ID(), err)
	}
	if err = session.ctx.localRW.Flush(); err != nil {
		log.Error("id=%s: got error while flushing response back to client: %v", session.ID(), err)
	}
	return err
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
