package main

import (
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
)

func main() {
	log.SetLevel(log.DEBUG)

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// Prepare the proxy.
	addr := &net.TCPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 3333,
	}

	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: addr,

		Username: "user",
		Password: "pass",
		APIHost:  "gomitmproxy",
	})

	err := proxy.Start()
	if err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Stop the proxy.
	proxy.Close()
}
