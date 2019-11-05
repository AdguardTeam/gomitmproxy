package gomitmproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
)

const defaultTimeout = 5 * time.Minute
const dialTimeout = 30 * time.Second
const tlsHandshakeTimeout = 10 * time.Second

// Proxy is a structure with the proxy server configuration and current state
type Proxy struct {
	transport http.RoundTripper

	// dial is a function for creating net.Conn
	// Can be useful to override in unit-tests
	dial func(string, string) (net.Conn, error)

	timeout time.Duration // Connection read/write timeout
	closing chan bool     // Channel that signals that proxy is closing

	conns   sync.WaitGroup // active connections
	connsMu sync.Mutex     // protects conns.Add/Wait from concurrent access

	// The proxy will not attempt MITM for these hostnames.
	// A hostname can be added to this list in runtime if proxy fails to verify the certificate.
	invalidTLSHosts   map[string]bool
	invalidTLSHostsMu sync.RWMutex

	Config // Proxy configuration
}

// NewProxy creates a new instance of the Proxy
func NewProxy(config Config) *Proxy {
	proxy := &Proxy{
		Config: config,
		transport: &http.Transport{
			// This forces http.Transport to not upgrade requests to HTTP/2
			// TODO: Remove when HTTP/2 can be supported
			TLSNextProto:          make(map[string]func(string, *tls.Conn) http.RoundTripper),
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ExpectContinueTimeout: time.Second,
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

// Closing returns true if the proxy is in the closing state
func (p *Proxy) Closing() bool {
	select {
	case <-p.closing:
		return true
	default:
		return false
	}
}

// Start starts the proxy server in a separate goroutine
func (p *Proxy) Start() error {
	// TODO: What if we want to use a TLS connection here?
	l, err := net.ListenTCP("tcp", p.ListenAddr)
	if err != nil {
		return err
	}

	go func() {
		log.Printf("start listening to %s", l.Addr())
		err := p.serve(l)
		if err != nil {
			log.Printf("finished serving due to: %v", err)
		}
		_ = l.Close()
	}()

	return nil
}

// Close sets the proxy to the closing state so it stops receiving new connections,
// finishes processing any inflight requests, and closes existing connections without
// reading anymore requests from them.
func (p *Proxy) Close() {
	log.Printf("Closing proxy")

	// This will prevent waiting for the proxy.timeout until an incoming request is read
	close(p.closing)

	log.Printf("Waiting for all active connections to close")
	p.connsMu.Lock()
	p.conns.Wait()
	p.connsMu.Unlock()
	log.Printf("All connections closed")
}

// serve accepts connections from the specified listener
// and passes them further to Proxy.handleConnection
func (p *Proxy) serve(l net.Listener) error {
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

// handleConnection starts processing a new network connection
func (p *Proxy) handleConnection(ctx *Context) {
	// Increment the active connections count
	p.connsMu.Lock()
	p.conns.Add(1)
	p.connsMu.Unlock()

	// Clean up on exit
	defer p.conns.Done()
	defer ctx.conn.Close()
	if p.Closing() {
		return
	}

	p.handleLoop(ctx)
}

// handleLoop processes requests in a loop
func (p *Proxy) handleLoop(ctx *Context) {
	for {
		// TODO: Add SetDeadline to *Context
		// Do it for the topmost parent conn only
		deadline := time.Now().Add(p.timeout)
		_ = ctx.conn.SetDeadline(deadline)

		if err := p.handleRequest(ctx); err != nil {
			log.Debug("id=%s: closing connection due to: %v", ctx.ID(), err)
			return
		}
	}
}

// handleRequest reads an incoming request and processes it
func (p *Proxy) handleRequest(ctx *Context) error {
	req, err := p.readRequest(ctx)
	if err != nil {
		return err
	}
	defer req.Body.Close()

	session := newSession(ctx, req)
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	log.Debug("id=%s: handle request to %s", session.ID(), req.URL.String())

	// connection, proxy-connection, etc, etc
	removeHopByHopHeaders(session.req.Header)

	// http by default
	req.URL.Scheme = "http"

	// check if this is an HTTPS connection inside an HTTP CONNECT tunnel
	if ctx.IsMITM() {
		tlsConn := ctx.conn.(*tls.Conn)
		cs := tlsConn.ConnectionState()
		req.TLS = &cs

		// force HTTPS for secure sessions
		req.URL.Scheme = "https"
	}

	req.RemoteAddr = ctx.conn.RemoteAddr().String()

	if req.Method == http.MethodConnect {
		return p.handleConnect(session)
	}

	// not a CONNECT request, processing HTTP request
	res, err := p.transport.RoundTrip(req)
	if err != nil {
		log.Error("id=%s: failed to round trip: %v", session.ID(), err)
		res = newErrorResponse(session.req, err)

		if strings.Contains(err.Error(), "x509: ") {
			log.Printf("id=%s: adding %s to invalid TLS hosts due to: %v", session.ID(), req.Host, err)
			p.invalidTLSHostsMu.Lock()
			p.invalidTLSHosts[req.Host] = true
			p.invalidTLSHostsMu.Unlock()
		}
	}
	defer res.Body.Close()

	log.Debug("id=%s: received response %s", session.ID(), res.Status)
	removeHopByHopHeaders(res.Header)
	session.res = res

	var closing error
	if req.Close || res.Close {
		log.Debug("id=%s: received close request", session.ID())
		res.Close = true
		closing = errClose
	}

	if p.Closing() {
		log.Debug("id=%s: proxy is shutting down, closing response", session.ID())
		res.Close = true
		closing = errClose
	}

	err = writeResponse(session)
	if err != nil {
		return err
	}
	return closing
}

// handleConnect processes HTTP CONNECT requests
func (p *Proxy) handleConnect(session *Session) error {
	log.Debug("id=%s: connecting to host: %s", session.ID(), session.req.URL.Host)

	remoteConn, err := p.dial("tcp", session.req.URL.Host)
	if err != nil {
		log.Error("id=%s: failed to connect to %s: %v", session.ID(), session.req.URL.Host, err)
		session.res = newErrorResponse(session.req, err)

		if err := session.res.Write(session.ctx.localRW); err != nil {
			log.Error("id=%s: got error while writing response back to client: %v", session.ID(), err)
		}
		err := session.ctx.localRW.Flush()
		if err != nil {
			log.Error("id=%s: got error while flushing response back to client: %v", session.ID(), err)
		}
		return err
	}

	if p.canMITM(session.req.URL.Host) {
		log.Debug("id=%s: attempting MITM for connection", session.ID())
		session.res = newResponse(http.StatusOK, nil, session.req)
		err = writeResponse(session)
		if err != nil {
			return err
		}

		b := make([]byte, 1)
		if _, err := session.ctx.localRW.Read(b); err != nil {
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

			// Handshake with the local client
			if err := tlsConn.Handshake(); err != nil {
				log.Error("id=%s: failed to handshake with the client: %v", session.ID(), err)
				return err
			}

			newLocalRW := bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
			newCtx := newContext(tlsConn, newLocalRW, session.ctx)
			p.handleLoop(newCtx)
			return errClose
		}

		newLocalRW := bufio.NewReadWriter(bufio.NewReader(pc), bufio.NewWriter(pc))
		newCtx := newContext(pc, newLocalRW, session.ctx)
		p.handleLoop(newCtx)
		return errClose
	}

	session.res = newResponse(http.StatusOK, nil, session.req)
	defer remoteConn.Close()
	defer session.res.Body.Close()

	session.res.ContentLength = -1
	err = writeResponse(session)
	if err != nil {
		return err
	}

	remoteW := bufio.NewWriter(remoteConn)
	remoteR := bufio.NewReader(remoteConn)
	defer remoteW.Flush()

	donec := make(chan bool, 2)
	go copyConnectTunnel(session, remoteW, session.ctx.localRW, donec)
	go copyConnectTunnel(session, session.ctx.localRW, remoteR, donec)

	log.Debug("id=%s: established CONNECT tunnel, proxying traffic", session.ID())
	<-donec
	<-donec
	log.Debug("id=%s: closed CONNECT tunnel", session.ID())

	return errClose
}

// copyConnectTunnel copies data from reader to writer
// and then signals about finishing to the "donec" channel
func copyConnectTunnel(session *Session, w io.Writer, r io.Reader, donec chan<- bool) {
	if _, err := io.Copy(w, r); err != nil && !isCloseable(err) {
		log.Error("id=%s: failed to copy CONNECT tunnel: %v", session.ID(), err)
	}

	log.Debug("id=%s: CONNECT tunnel finished copying", session.ID())
	donec <- true
}

// readRequest reads incoming http request in
func (p *Proxy) readRequest(ctx *Context) (*http.Request, error) {
	log.Debug("id=%s: waiting for request", ctx.ID())

	var req *http.Request
	reqc := make(chan *http.Request, 1)
	errc := make(chan error, 1)

	// Try reading the HTTP request in a separate goroutine. The idea is to make this process cancelable.
	// When reading request is finished, it will write the results to one of the channels -- either reqc or errc.
	// At the same time we'll be reading from the "closing" channel.
	// When proxy is shutting down, the "closing" channel is closed so we'll immediately return.
	go func() {
		r, err := http.ReadRequest(ctx.localRW.Reader)
		if err != nil {
			if isCloseable(err) {
				log.Debug("id=%s: connection closed prematurely: %v", ctx.ID(), err)
			} else {
				log.Debug("id=%s: failed to read request: %v", ctx.ID(), err)
			}

			errc <- err
			return
		}
		reqc <- r
	}()

	// Waiting for the result or for proxy to shutdown
	select {
	case err := <-errc:
		return nil, err
	case req = <-reqc:
	case <-p.closing:
		return nil, errShutdown
	}

	return req, nil
}

// canMITM checks if we can perform MITM for this host
func (p *Proxy) canMITM(hostname string) bool {
	if p.MITMConfig == nil {
		return false
	}

	// Remove the port if it exists.
	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}

	p.invalidTLSHostsMu.RLock()
	_, found := p.invalidTLSHosts[hostname]
	p.invalidTLSHostsMu.RUnlock()
	return !found
}
