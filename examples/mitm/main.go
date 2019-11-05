package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"os/signal"
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

	mitmConfig, err := mitm.NewConfig(x509c, priv)

	// PREPARE PROXY
	addr := &net.TCPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 3333,
	}

	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: addr,
		MITMConfig: mitmConfig,
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
