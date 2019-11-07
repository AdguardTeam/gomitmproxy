[![Build Status](https://travis-ci.com/AdguardTeam/gomitmproxy.svg?branch=master)](https://travis-ci.com/AdguardTeam/gomitmproxy)
[![Code Coverage](https://img.shields.io/codecov/c/github/AdguardTeam/gomitmproxy/master.svg)](https://codecov.io/github/AdguardTeam/gomitmproxy?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/AdguardTeam/gomitmproxy)](https://goreportcard.com/report/AdguardTeam/gomitmproxy)
[![GolangCI](https://golangci.com/badges/github.com/AdguardTeam/gomitmproxy.svg)](https://golangci.com/r/github.com/AdguardTeam/gomitmproxy)
[![Go Doc](https://godoc.org/github.com/AdguardTeam/gomitmproxy?status.svg)](https://godoc.org/github.com/AdguardTeam/gomitmproxy)

# gomitmproxy

This is a customizable HTTP proxy with TLS interception support.
It was created as a part of [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome).
However, it can be used for different purposes so we decided to make it a separate project.

## Features
 
* HTTP proxy
* HTTP over TLS (HTTPS) proxy
* Proxy authorization
* TLS termination

## How to use gomitmproxy

### Simple HTTP proxy

```go
package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/AdguardTeam/gomitmproxy"
)

func main() {
	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: 8080,
		},
	})
	err := proxy.Start()
	if err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Clean up
	proxy.Close()
}
```

### Modifying requests and responses

You can modify requests and responses by setting `OnRequest` and `OnResponse` handlers.

```go
proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
    ListenAddr: &net.TCPAddr{
        IP:   net.IPv4(0, 0, 0, 0),
        Port: 8080,
    },
    OnRequest: func(session *gomitmproxy.Session) (request *http.Request, response *http.Response) {
        req := session.Request()

        log.Printf("onRequest: %s %s", req.Method, req.URL.String())

        if req.URL.Host == "example.net" {
            body := strings.NewReader("<html><body><h1>Replaced response</h1></body></html>")
            res := gomitmproxy.NewResponse(http.StatusOK, body, req)
            res.Header.Set("Content-Type", "text/html")

            // Use session props to pass the information about request being blocked
            session.SetProp("blocked", true)
            return nil, res
        }

        return nil, nil
    },
    OnResponse: func(session *gomitmproxy.Session) *http.Response {
        log.Printf("onResponse: %s", session.Request().URL.String())

        if _, ok := session.GetProp("blocked"); ok {
            log.Printf("onResponse: was blocked")
        }

        return nil
    },
})
```

### Proxy authorization

If you want to protect your proxy with Basic authentication, set `Username` and `Password`
fields in the proxy configuration.

```go
proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
    ListenAddr: &net.TCPAddr{
        IP:   net.IPv4(0, 0, 0, 0),
        Port: 8080,
    },
    Username: "user",
    Password: "pass",
})
```

### HTTP over TLS (HTTPS) proxy

If you want to protect yourself from eavesdropping on your traffic to proxy, you can configure
it to work over a TLS tunnel. This is really simple to do, just set a `*tls.Config` instance
in your proxy configuration.

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{*proxyCert},
}
proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
    ListenAddr: addr,
    TLSConfig:  tlsConfig,
})
```

### TLS interception

If you want to do TLS termination, you first need to prepare a self-signed certificate
that will be used as a certificates authority. Use the following `openssl` commands to do this.

```bash
openssl genrsa -out demo.key 2048
openssl req -new -x509 -key demo.key -out demo.crt
```

Now you can use it to initialize `MITMConfig`:
```go
tlsCert, err := tls.LoadX509KeyPair("demo.crt", "demo.key")
if err != nil {
    log.Fatal(err)
}
privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
if err != nil {
    log.Fatal(err)
}

mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
if err != nil {
    log.Fatal(err)
}

mitmConfig.SetValidity(time.Hour * 24 * 7) // generate certs valid for 7 days
mitmConfig.SetOrganization("gomitmproxy")  // cert organization
```

Please note that you can set `MITMExceptions` to a list of hostnames,
which will be excluded from TLS interception.

```go
proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
    ListenAddr: &net.TCPAddr{
        IP:   net.IPv4(0, 0, 0, 0),
        Port: 3333,
    },
    MITMConfig:     mitmConfig,
    MITMExceptions: []string{"example.com"},
})
```

### Custom certs storage

By default, `gomitmproxy` uses an in-memory map-based storage for the certificates,
generated while doing TLS interception. It is often necessary to use a different kind
of certificates storage. If this is your case, you can supply your own implementation
of the `CertsStorage` interface.

```go
// CustomCertsStorage - an example of a custom cert storage
type CustomCertsStorage struct {
	certsCache map[string]*tls.Certificate // cache with the generated certificates
}

// Get gets the certificate from the storage
func (c *CustomCertsStorage) Get(key string) (*tls.Certificate, bool) {
	v, ok := c.certsCache[key]
	return v, ok
}

// Set saves the certificate to the storage
func (c *CustomCertsStorage) Set(key string, cert *tls.Certificate) {
	c.certsCache[key] = cert
}
```

Then pass it to the `NewConfig` function.

```go
mitmConfig, err := mitm.NewConfig(x509c, privateKey, &CustomCertsStorage{
    certsCache: map[string]*tls.Certificate{}},
)
```

## Notable alternatives

* [martian](https://github.com/google/martian) - an awesome debugging proxy with TLS interception support.
* [goproxy](https://github.com/elazarl/goproxy) - also supports TLS interception and requests. 

## TODO

* [X] Basic HTTP proxy without MITM
* [ ] Proxy
    * [X] Expose APIs for the library users
    * [X] How-to doc
    * [X] Travis configuration
    * [X] Proxy-Authorization
    * [ ] Unit tests
    * [ ] WebSockets support (see [this](https://github.com/google/martian/issues/31))
    * [X] `certsCache` -- allow custom implementations
    * [X] Support HTTP CONNECT over TLS
    * [ ] Test plain HTTP requests inside HTTP CONNECT
    * [ ] Test memory leaks
    * [ ] Check & fix TODOs
* [ ] MITM
    * [X] Basic MITM
    * [X] MITM exceptions
    * [X] Handle invalid server certificates properly (not just reset connections)
    * [X] Pass the most important tests on badssl.com/dashboard
    * [X] Handle certificate authentication
    * [ ] Allow configuring minimum supported TLS version
    * [ ] OCSP check (see [example](https://stackoverflow.com/questions/46626963/golang-sending-ocsp-request-returns))
    * [ ] (?) HPKP (see [example](https://github.com/tam7t/hpkp))
    * [ ] (?) CT logs (see [example](https://github.com/google/certificate-transparency-go))
    * [ ] (?) CRLSets (see [example](https://github.com/agl/crlset-tools))