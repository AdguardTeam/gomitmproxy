// Package proxyutil contains different utility methods that will be helpful to
// gomitmproxy users.
package proxyutil

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

// NewResponse builds a new HTTP response. If body is nil, an empty byte.Buffer
// will be provided to be consistent with the guarantees provided by
// http.Transport and http.Client.
func NewResponse(code int, body io.Reader, req *http.Request) (resp *http.Response) {
	if body == nil {
		body = &bytes.Buffer{}
	}

	rc, ok := body.(io.ReadCloser)
	if !ok {
		rc = io.NopCloser(body)
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

// NewErrorResponse creates a new HTTP response with status code
// "502 Bad Gateway". "Warning" header is populated with the error details.
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Warning.
func NewErrorResponse(req *http.Request, err error) (resp *http.Response) {
	resp = NewResponse(http.StatusBadGateway, nil, req)
	resp.Close = true

	date := resp.Header.Get("Date")
	if date == "" {
		date = time.Now().Format(http.TimeFormat)
	}

	w := fmt.Sprintf(`199 "gomitmproxy" %q %q`, err.Error(), date)
	resp.Header.Add("Warning", w)
	return resp
}

// ReadDecompressedBody reads full response body and decompresses it if
// necessary.
func ReadDecompressedBody(res *http.Response) (b []byte, err error) {
	rBody := res.Body
	if res.Header.Get("Content-Encoding") == "gzip" {
		var gzReader io.ReadCloser
		gzReader, err = gzip.NewReader(rBody)
		if err != nil {
			return nil, err
		}
		rBody = gzReader
		defer gzReader.Close()
	}

	return io.ReadAll(rBody)
}

// DecodeLatin1 decodes Latin1 string from the reader. This method is useful
// for editing response bodies when you don't want to handle different
// encodings.
func DecodeLatin1(reader io.Reader) (str string, err error) {
	r := transform.NewReader(reader, charmap.ISO8859_1.NewDecoder())
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// EncodeLatin1 encodes the string as a byte array using Latin1.
func EncodeLatin1(str string) ([]byte, error) {
	return charmap.ISO8859_1.NewEncoder().Bytes([]byte(str))
}

// NoopConn is a struct that implements net.Conn and does nothing.
type NoopConn struct{}

// LocalAddr always returns 0.0.0.0:0.
func (NoopConn) LocalAddr() net.Addr { return &net.TCPAddr{} }

// RemoteAddr always returns 0.0.0.0:0.
func (NoopConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }

// SetDeadline does nothing, returns nil.
func (NoopConn) SetDeadline(time.Time) error { return nil }

// SetReadDeadline does nothing, returns nil.
func (NoopConn) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline does nothing, returns nil.
func (NoopConn) SetWriteDeadline(time.Time) error { return nil }

// Read does nothing, returns io.EOF.
func (NoopConn) Read(b []byte) (int, error) { return 0, io.EOF }

// Write does nothing, returns len(b).
func (NoopConn) Write(b []byte) (int, error) { return len(b), nil }

// Close does nothing, returns nil.
func (NoopConn) Close() error { return nil }
