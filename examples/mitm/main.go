package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ameshkov/gomitmproxy/mitm"

	"github.com/AdguardTeam/golibs/log"

	"github.com/ameshkov/gomitmproxy"
)

func main() {
	log.SetLevel(log.DEBUG)

	// READ CERT AND KEY
	tlsc, err := tls.LoadX509KeyPair("demo.crt", "demo.key")
	if err != nil {
		log.Fatal(err)
	}
	priv := tlsc.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsc.Certificate[0])
	if err != nil {
		panic(err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, priv, nil)
	if err != nil {
		panic(err)
	}

	//
	proxyCert, err := mitmConfig.GetOrCreateCert("127.0.0.1")
	if err != nil {
		panic(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*proxyCert},
	}

	// PREPARE PROXY
	addr := &net.TCPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 3333,
	}

	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: addr,
		TLSConfig:  tlsConfig,

		Username: "user",
		Password: "pass",

		MITMConfig:     mitmConfig,
		MITMExceptions: []string{"example.com"},

		OnRequest:  onRequest,
		OnResponse: onResponse,
	})

	err = proxy.Start()
	if err != nil {
		panic(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	proxy.Close()
}

func onRequest(session *gomitmproxy.Session) (*http.Request, *http.Response) {
	req := session.Request()

	log.Printf("onRequest: %s %s", req.Method, req.URL.String())

	if req.URL.Host == "example.net" {
		body := strings.NewReader("<html><body><h1>Replaced response</h1></body></html>")
		res := gomitmproxy.NewResponse(http.StatusOK, body, req)
		res.Header.Set("Content-Type", "text/html")
		session.SetProp("blocked", true)
		return nil, res
	}

	return nil, nil
}

func onResponse(session *gomitmproxy.Session) *http.Response {
	log.Printf("onResponse: %s", session.Request().URL.String())

	if _, ok := session.GetProp("blocked"); ok {
		log.Printf("onResponse: was blocked")
	}

	return nil
}
