// Package gomitmproxy implements a configurable mitm proxy wring purely in go.
package gomitmproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy/proxyutil"
	"github.com/pkg/errors"
)

var errClientCertRequested = errors.New("tls: client cert authentication unsupported")

// defaultTimeout is the default value for reading from local connections.
// By default we have no timeout.
//
// TODO(ameshkov): rework deadlines (see #13 for example).
const defaultTimeout = 0
const dialTimeout = 30 * time.Second
const tlsHandshakeTimeout = 10 * time.Second

// Proxy is a structure with the proxy server configuration and current state.
type Proxy struct {
	// addr is the address the proxy listens to.
	addr net.Addr

	// transport is an http.RoundTripper instance that we use for plain HTTP
	// requests.
	transport http.RoundTripper

	// listener is used to accept incoming connections to this proxy.
	listener net.Listener

	// dial is a function for creating net.Conn. Can be useful to override in
	// unit-tests.
	dial func(string, string) (net.Conn, error)

	// timeout is the remote connection's read/write timeout.
	timeout time.Duration

	// closing is the channel that signals that proxy is closing.
	closing chan bool

	// connsWg is a wait group that's used to keep track of active connections.
	connsWg sync.WaitGroup

	// The proxy will not attempt MITM for these hostnames. A hostname can be
	// added to this list in runtime if proxy fails to verify the certificate.
	invalidTLSHosts   map[string]bool
	invalidTLSHostsMu sync.RWMutex

	// Config is the proxy's configuration.
	// TODO(ameshkov): make it a field.
	Config
}

// NewProxy creates a new instance of the Proxy.
func NewProxy(config Config) *Proxy {
	proxy := &Proxy{
		Config: config,
		transport: &http.Transport{
			// This forces http.Transport to not upgrade requests to HTTP/2.
			// TODO: Remove when HTTP/2 can be supported.
			TLSNextProto:          make(map[string]func(string, *tls.Conn) http.RoundTripper),
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ExpectContinueTimeout: time.Second,
			TLSClientConfig: &tls.Config{
				GetClientCertificate: func(info *tls.CertificateRequestInfo) (certificate *tls.Certificate, e error) {
					// We purposefully cause an error here so that the
					// http.Transport.RoundTrip method failed. In this case
					// we'll receive the error and will be able to add the host
					// to invalidTLSHosts.
					return nil, errClientCertRequested
				},
			},
		},
		timeout:         defaultTimeout,
		invalidTLSHosts: map[string]bool{},
		closing:         make(chan bool),
	}
	proxy.dial = (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: dialTimeout,
	}).Dial

	if len(config.MITMExceptions) > 0 {
		for _, hostname := range config.MITMExceptions {
			proxy.invalidTLSHosts[hostname] = true
		}
	}

	return proxy
}

// Addr returns the address this proxy listens to.
func (p *Proxy) Addr() (addr net.Addr) {
	return p.addr
}

// Closing returns true if the proxy is in the closing state.
func (p *Proxy) Closing() (ok bool) {
	select {
	case <-p.closing:
		return true
	default:
		return false
	}
}

// Start starts the proxy server in a separate goroutine.
func (p *Proxy) Start() (err error) {
	l, err := net.ListenTCP("tcp", p.ListenAddr)
	if err != nil {
		return err
	}
	p.addr = l.Addr()

	var listener net.Listener
	listener = l
	if p.TLSConfig != nil {
		listener = tls.NewListener(l, p.TLSConfig)
	}

	p.listener = listener
	go p.Serve(listener)
	return nil
}

// Serve starts reading and processing requests from the specified listener.
// Please note, that it will close the listener in the end.
func (p *Proxy) Serve(l net.Listener) {
	log.Printf("start listening to %s", l.Addr())
	err := p.serve(l)
	if err != nil {
		log.Printf("finished serving due to: %v", err)
	}
	_ = l.Close()
}

// Close sets the proxy to the closing state so it stops receiving new
// connections, finishes processing any inflight requests, and closes existing
// connections without reading anymore requests from them.
//
// TODO(ameshkov): make it return an error.
func (p *Proxy) Close() {
	log.Printf("Closing proxy")

	log.OnCloserError(p.listener, log.DEBUG)

	// This will prevent waiting for the proxy.timeout until an incoming
	// request has been read.
	close(p.closing)

	log.Printf("Waiting for all active connections to close")
	p.connsWg.Wait()
	log.Printf("All connections closed")
}

// serve accepts connections from the specified listener and passes them further
// to Proxy.handleConnection.
func (p *Proxy) serve(l net.Listener) (err error) {
	for {
		if p.Closing() {
			return nil
		}

		conn, err := l.Accept()
		if err != nil {
			return err
		}

		localRW := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		ctx := newContext(conn, localRW, nil)
		log.Debug("id=%s: accepted connection from %s", ctx.ID(), ctx.conn.RemoteAddr())

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(3 * time.Minute)
		}

		go p.handleConnection(ctx)
	}
}

// handleConnection starts processing a new network connection.
func (p *Proxy) handleConnection(ctx *Context) {
	// Increment the active connections count.
	p.connsWg.Add(1)

	// Clean up on exit.
	defer p.connsWg.Done()
	defer log.OnCloserError(ctx.conn, log.DEBUG)

	if p.Closing() {
		return
	}

	p.handleLoop(ctx)
}

// handleLoop processes requests in a loop.
func (p *Proxy) handleLoop(ctx *Context) {
	for {
		if p.timeout > 0 {
			// TODO(ameshkov): rework deadlines (see #13 for example).
			deadline := time.Now().Add(p.timeout)
			_ = ctx.SetDeadline(deadline)
		}

		if err := p.handleRequest(ctx); err != nil {
			log.Debug("id=%s: closing connection due to: %v", ctx.ID(), err)

			return
		}
	}
}

// handleRequest reads an incoming request and processes it.
func (p *Proxy) handleRequest(ctx *Context) (err error) {
	origReq, err := p.readRequest(ctx)

	defer log.OnCloserError(origReq.Body, log.DEBUG)

	if err != nil {
		return err
	}

	session := newSession(ctx, origReq)
	p.prepareRequest(origReq, session)
	log.Debug("id=%s: handle request %s %s", session.ID(), origReq.Method, origReq.URL.String())

	customRes := false
	if p.OnRequest != nil {
		newReq, newRes := p.OnRequest(session)
		if newReq != nil {
			log.Debug("id=%s: request was overridden by: %s", session.ID(), newReq.URL.String())
			session.req = newReq
		}
		if newRes != nil {
			log.Debug("id=%s: response was overridden by: %s", session.ID(), newRes.Status)
			session.res = newRes
			customRes = true
		}
	}

	if session.req.Host == p.APIHost {
		return p.handleAPIRequest(session)
	}

	if !customRes {
		// check proxy authorization first.
		if p.Username != "" {
			auth, res := p.authorize(session)
			if !auth {
				log.Debug("id=%s: proxy auth required", session.ID())
				session.res = res

				defer log.OnCloserError(res.Body, log.DEBUG)

				_ = p.writeResponse(session)

				// Do not return any error here as we must keep the connection
				// alive. When the client receives 407 error, it can write
				// another request with user credentials to the same connection.
				// See https://github.com/AdguardTeam/gomitmproxy/pull/19.
				return nil
			}
		}

		if session.req.Header.Get("Upgrade") == "websocket" {
			// connection protocol will be upgraded.
			return p.handleTunnel(session)
		}

		// connection, proxy-connection, etc, etc.
		removeHopByHopHeaders(session.req.Header)

		if session.req.Method == http.MethodConnect {
			return p.handleConnect(session)
		}

		// not a CONNECT request, processing a plain HTTP request.
		res, err := p.transport.RoundTrip(session.req)
		if err != nil {
			log.Error("id=%s: failed to round trip: %v", session.ID(), err)
			p.raiseOnError(session, err)

			res = proxyutil.NewErrorResponse(session.req, err)

			if strings.Contains(err.Error(), "x509: ") ||
				strings.Contains(err.Error(), errClientCertRequested.Error()) {
				log.Printf("id=%s: adding %s to invalid TLS hosts due to: %v", session.ID(), session.req.Host, err)
				p.invalidTLSHostsMu.Lock()
				p.invalidTLSHosts[session.req.Host] = true
				p.invalidTLSHostsMu.Unlock()
			}
		}

		log.Debug("id=%s: received response %s", session.ID(), res.Status)
		removeHopByHopHeaders(res.Header)
		session.res = res
	}

	// Make sure the response body is always closed.
	defer log.OnCloserError(session.res.Body, log.DEBUG)

	err = p.writeResponse(session)
	if err != nil {
		return err
	}

	// TODO(ameshkov): Think about refactoring this, looks not good
	if p.isClosing(session) {
		return errClose
	}

	if p.Closing() {
		log.Debug("id=%s: proxy is shutting down, closing response", session.ID())
		return errShutdown
	}

	return nil
}

// handleAPIRequest handles a request to gomitmproxy's API.
func (p *Proxy) handleAPIRequest(session *Session) (err error) {
	if session.req.URL.Path == "/cert.crt" && p.MITMConfig != nil {
		// serve ca
		b := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: p.MITMConfig.GetCA().Raw,
		})

		session.res = proxyutil.NewResponse(http.StatusOK, bytes.NewReader(b), session.req)
		defer log.OnCloserError(session.res.Body, log.DEBUG)

		session.res.Close = true
		session.res.Header.Set("Content-Type", "application/x-x509-ca-cert")
		session.res.ContentLength = int64(len(b))

		return p.writeResponse(session)
	}

	session.res = proxyutil.NewErrorResponse(session.req, errors.Errorf("wrong API method"))
	defer log.OnCloserError(session.res.Body, log.DEBUG)

	session.res.Close = true

	return p.writeResponse(session)
}

// isClosing returns true if this session's response or request signals that
// the connection must be closed.
func (p *Proxy) isClosing(session *Session) (ok bool) {
	// See http.Response.Write implementation for the details on this.
	//
	// If we're sending a non-chunked HTTP/1.1 response without a
	// content-length, the only way to do that is the old HTTP/1.0 way, by
	// noting the EOF with a connection close, so we need to set Close.
	if (session.res.ContentLength == 0 || session.res.ContentLength == -1) &&
		!session.res.Close &&
		session.res.ProtoAtLeast(1, 1) &&
		!session.res.Uncompressed &&
		(len(session.res.TransferEncoding) == 0 || session.res.TransferEncoding[0] != "chunked") {
		log.Debug("id=%s: received close request (http/1.0 way)", session.ID())

		return true
	}

	if session.req.Close || session.res.Close {
		log.Debug("id=%s: received close request", session.ID())

		return true
	}

	return false
}

// handleTunnel tunnels data to the remote connection.
func (p *Proxy) handleTunnel(session *Session) (err error) {
	log.Debug("id=%s: handling connection to host: %s", session.ID(), session.req.URL.Host)

	conn, err := p.connect(session, "tcp", session.RemoteAddr())
	if err != nil {
		log.Error("id=%s: failed to connect to %s: %v", session.ID(), session.req.URL.Host, err)
		p.raiseOnError(session, err)
		session.res = proxyutil.NewErrorResponse(session.req, err)
		_ = p.writeResponse(session)
		log.OnCloserError(session.res.Body, log.DEBUG)

		return err
	}

	remoteConn := conn
	defer log.OnCloserError(remoteConn, log.DEBUG)

	// If we're inside a MITMed connection, we should open a TLS connection
	// instead.
	if session.ctx.IsMITM() {
		getClientCert := func(
			info *tls.CertificateRequestInfo,
		) (certificate *tls.Certificate, e error) {
			// We purposefully cause an error here so that the
			// http.Transport.RoundTrip method failed. In this case we'll
			// receive the error and will be able to add the host to
			// invalidTLSHosts.
			return nil, errClientCertRequested
		}

		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:           session.req.URL.Host,
			GetClientCertificate: getClientCert,
		})

		// Handshake with the remote server.
		if err = tlsConn.Handshake(); err != nil {
			// TODO(ameshkov): Consider adding to invalidTLSHosts.
			// We should do this if this happens a couple of times in a short
			// period of time.
			log.Error("id=%s: failed to handshake with the server: %v", session.ID(), err)

			return err
		}

		// Prepare to process the data.
		remoteConn = tlsConn
	}

	// Write the original request to the connection.
	err = session.req.Write(remoteConn)
	if err != nil {
		log.Error("id=%s: failed to write request: %v", session.ID(), err)

		return err
	}

	// Note that we don't use buffered reader/writer for local connection as it
	// causes a noticeable delay when we work as an HTTP over TLS proxy.
	donec := make(chan bool, 2)
	go copyConnectTunnel(session, remoteConn, session.ctx.conn, donec)
	go copyConnectTunnel(session, session.ctx.conn, remoteConn, donec)

	log.Debug("id=%s: established tunnel, proxying traffic", session.ID())
	<-donec
	<-donec
	log.Debug("id=%s: closed tunnel", session.ID())

	return errClose
}

// handleConnect processes HTTP CONNECT requests.
func (p *Proxy) handleConnect(session *Session) (err error) {
	log.Debug("id=%s: connecting to host: %s", session.ID(), session.req.URL.Host)

	// TODO(ameshkov): find a way to use remoteConn when the request is MITMed.
	remoteConn, err := p.connect(session, "tcp", session.RemoteAddr())
	if remoteConn != nil {
		defer log.OnCloserError(remoteConn, log.DEBUG)
	}

	if err != nil {
		log.Error("id=%s: failed to connect to %s: %v", session.ID(), session.req.URL.Host, err)
		p.raiseOnError(session, err)

		session.res = proxyutil.NewErrorResponse(session.req, err)
		_ = p.writeResponse(session)
		defer log.OnCloserError(session.res.Body, log.DEBUG)

		return err
	}

	if p.canMITM(session.req.URL.Host) {
		log.Debug("id=%s: attempting MITM for connection", session.ID())
		session.res = proxyutil.NewResponse(http.StatusOK, nil, session.req)
		err = p.writeResponse(session)

		log.OnCloserError(session.res.Body, log.DEBUG)

		if err != nil {
			return err
		}

		b := make([]byte, 1)
		if _, err = session.ctx.localRW.Read(b); err != nil {
			log.Error("id=%s: error peeking message through CONNECT tunnel to determine type: %v", session.ID(), err)
			return err
		}

		// Drain all of the rest of the buffered data.
		buf := make([]byte, session.ctx.localRW.Reader.Buffered())
		_, _ = session.ctx.localRW.Read(buf)

		// Prepend the previously read data to be read again by
		// http.ReadRequest.
		pc := &peekedConn{
			session.ctx.conn,
			io.MultiReader(bytes.NewReader(b), bytes.NewReader(buf), session.ctx.conn),
		}

		// 22 is the TLS handshake.
		// https://tools.ietf.org/html/rfc5246#section-6.2.1
		if b[0] == 22 {
			tlsConn := tls.Server(pc, p.MITMConfig.NewTLSConfigForHost(session.req.URL.Host))

			// Handshake with the local client.
			if err = tlsConn.Handshake(); err != nil {
				// TODO(ameshkov): Consider adding to invalidTLSHosts.
				// We should do this if this happens a couple of times in a
				// short period of time.
				log.Error("id=%s: failed to handshake with the client: %v", session.ID(), err)

				return err
			}

			newLocalRW := bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
			newCtx := newContext(tlsConn, newLocalRW, session)
			p.handleLoop(newCtx)

			return errClose
		}

		newLocalRW := bufio.NewReadWriter(bufio.NewReader(pc), bufio.NewWriter(pc))
		newCtx := newContext(pc, newLocalRW, session)
		p.handleLoop(newCtx)

		return errClose
	}

	session.res = proxyutil.NewResponse(http.StatusOK, nil, session.req)
	defer log.OnCloserError(session.res.Body, log.DEBUG)

	session.res.ContentLength = -1
	err = p.writeResponse(session)
	if err != nil {
		return err
	}

	// Note that we don't use buffered reader/writer for local connection
	// as it causes a noticeable delay when we work as an HTTP over TLS proxy
	donec := make(chan bool, 2)
	go copyConnectTunnel(session, remoteConn, session.ctx.conn, donec)
	go copyConnectTunnel(session, session.ctx.conn, remoteConn, donec)

	log.Debug("id=%s: established CONNECT tunnel, proxying traffic", session.ID())
	<-donec
	<-donec
	log.Debug("id=%s: closed CONNECT tunnel", session.ID())

	return errClose
}

// copyConnectTunnel copies data from reader to writer and then signals about
// finishing to the "donec" channel.
func copyConnectTunnel(session *Session, w io.Writer, r io.Reader, donec chan<- bool) {
	if _, err := io.Copy(w, r); err != nil && !isCloseable(err) {
		log.Error("id=%s: failed to tunnel: %v", session.ID(), err)
	}

	log.Debug("id=%s: tunnel finished copying", session.ID())
	donec <- true
}

// readRequest reads incoming http request.
func (p *Proxy) readRequest(ctx *Context) (req *http.Request, err error) {
	log.Debug("id=%s: waiting for request", ctx.ID())

	reqc := make(chan *http.Request, 1)
	errc := make(chan error, 1)

	// Try reading the HTTP request in a separate goroutine. The idea is to make
	// this process cancelable. When reading the request is finished, it will
	// write the results to one of the channels, either reqc or errc. At the
	// same time we'll be reading from the "closing" channel. When the proxy is
	// shutting down, the "closing" channel is closed so we'll immediately
	// return.
	go func() {
		r, readErr := http.ReadRequest(ctx.localRW.Reader)
		if readErr != nil {
			if isCloseable(readErr) {
				log.Debug("id=%s: connection closed prematurely: %v", ctx.ID(), readErr)
			} else {
				log.Debug("id=%s: failed to read request: %v", ctx.ID(), readErr)
			}

			errc <- readErr
			return
		}
		reqc <- r
	}()

	// Waiting for the result or for proxy to shutdown
	select {
	case err = <-errc:
		return nil, err
	case req = <-reqc:
	case <-p.closing:
		return nil, errShutdown
	}

	return req, nil
}

// writeResponse writes the response from session.res to the local client.
func (p *Proxy) writeResponse(session *Session) (err error) {
	if p.OnResponse != nil {
		res := p.OnResponse(session)
		if res != nil {
			origBody := res.Body
			defer log.OnCloserError(origBody, log.DEBUG)
			log.Debug("id=%s: response was overridden by: %s", session.ID(), res.Status)
			session.res = res
		}
	}

	if err = session.res.Write(session.ctx.localRW); err != nil {
		log.Error(
			"id=%s: got error while writing response back to client: %v",
			session.ID(),
			err,
		)
	}

	if err = session.ctx.localRW.Flush(); err != nil {
		log.Error(
			"id=%s: got error while flushing response back to client: %v",
			session.ID(),
			err,
		)
	}

	return err
}

// connect opens a network connection to the specified remote address.
//
// This method can be called in two cases:
//  1. When the proxy handles the HTTP CONNECT.
//     IMPORTANT: In this case we don't actually use the remote connections.
//     It is only used to check if the remote endpoint is available
//  2. When the proxy bypasses data from the client to the remote endpoint.
//     For instance, it could happen when there's a WebSocket connection.
func (p *Proxy) connect(session *Session, proto string, addr string) (conn net.Conn, err error) {
	log.Debug("id=%s: connecting to %s://%s", session.ID(), proto, addr)

	if p.OnConnect != nil {
		conn = p.OnConnect(session, proto, addr)
		if conn != nil {
			log.Debug("id=%s: connection was overridden", session.ID())

			return conn, nil
		}
	}

	host, _, err := net.SplitHostPort(addr)
	if err == nil && host == p.APIHost {
		log.Debug("id=%s: connecting to the API host, return dummy connection", session.ID())

		return &proxyutil.NoopConn{}, nil
	}

	return p.dial(proto, addr)
}

// prepareRequest prepares an HTTP request to be sent to the remote server.
func (p *Proxy) prepareRequest(req *http.Request, session *Session) {
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	// http by default.
	req.URL.Scheme = "http"

	// Check if this is an HTTPS connection inside an HTTP CONNECT tunnel.
	if session.ctx.IsMITM() {
		tlsConn := session.ctx.conn.(*tls.Conn)
		cs := tlsConn.ConnectionState()
		req.TLS = &cs

		// Force HTTPS for secure sessions.
		req.URL.Scheme = "https"
	}
	req.RemoteAddr = session.ctx.conn.RemoteAddr().String()

	// Remove unsupported encodings.
	if req.Header.Get("Accept-Encoding") != "" {
		req.Header.Set("Accept-Encoding", "gzip")
	}
}

// raiseOnError calls Proxy.OnError callback if needed.
func (p *Proxy) raiseOnError(session *Session, err error) {
	if p.OnError != nil {
		p.OnError(session, err)
	}
}

// canMITM checks if we can perform MITM for this host.
func (p *Proxy) canMITM(hostname string) (ok bool) {
	if p.MITMConfig == nil {
		return false
	}

	// Remove the port if it exists.
	host, port, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}

	// TODO(ameshkov): change this, should be exposed via a callback.
	if port != "443" {
		log.Debug("do not attempt to MITM connections to a port different from 443")

		return false
	}

	p.invalidTLSHostsMu.RLock()
	_, found := p.invalidTLSHosts[hostname]
	p.invalidTLSHostsMu.RUnlock()

	return !found
}
