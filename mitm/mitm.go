// Package mitm implements methods for working with certificates and TLS configurations
// that are used for mitming connections.
package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/golibs/log"
)

// While generating a new certificate, in order to get a unique serial
// number every time we increment this value.
var currentSerialNumber int64 = time.Now().Unix()

// Config is a set of configuration values that are used to build TLS configs
// capable of MITM.
type Config struct {
	ca           *x509.Certificate // Root certificate authority
	caPrivateKey *rsa.PrivateKey   // CA private key

	// roots is a CertPool that contains the root CA GetOrCreateCert
	// it serves a single purpose -- to verify the cached domain certs
	roots *x509.CertPool

	// privateKey is the private key that will be used to generate leaf certificates
	// TODO: insecure approach, generating a new key would be better
	privateKey *rsa.PrivateKey

	validity     time.Duration // Validity of the generated certificates
	keyID        []byte        // SKI to use in generated certificates (https://tools.ietf.org/html/rfc3280#section-4.2.1.2)
	organization string        // Organization (will be used for generated certificates)

	certsStorage   CertsStorage // cache with the generated certificates
	certsStorageMu sync.RWMutex
}

// CertsStorage is an interface for generated tls certificates storage
type CertsStorage interface {
	// Get gets the certificate from the storage
	Get(key string) (*tls.Certificate, bool)
	// Set saves the certificate to the storage
	Set(key string, cert *tls.Certificate)
}

// CertsCache is a simple map-based CertsStorage implementation
type CertsCache struct {
	certsCache map[string]*tls.Certificate // cache with the generated certificates
}

// Get gets the certificate from the storage
func (c *CertsCache) Get(key string) (*tls.Certificate, bool) {
	v, ok := c.certsCache[key]
	return v, ok
}

// Set saves the certificate to the storage
func (c *CertsCache) Set(key string, cert *tls.Certificate) {
	c.certsCache[key] = cert
}

// NewAuthority creates a new CA certificate and associated private key.
// name -- certificate subject name
// organization -- certificate organization
// validity -- time for which the certificate is valid
func NewAuthority(name, organization string, validity time.Duration) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://tools.ietf.org/html/rfc3280#section-4.2.1.2
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	h := sha1.New()
	_, err = h.Write(pkixpub)
	if err != nil {
		return nil, nil, err
	}
	keyID := h.Sum(nil)

	// Increment the serial number
	serial := atomic.AddInt64(&currentSerialNumber, 1)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{organization},
		},
		SubjectKeyId:          keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-validity),
		NotAfter:              time.Now().Add(validity),
		DNSNames:              []string{name},
		IsCA:                  true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return x509c, priv, nil
}

// NewConfig creates a new MITM configuration
// ca -- root certificate authority to use for generating domain certs
// privateKey -- private key of this CA GetOrCreateCert
// storage -- a custom certs storage or null if you want to use the default implementation
func NewConfig(ca *x509.Certificate, privateKey *rsa.PrivateKey, storage CertsStorage) (*Config, error) {
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	// Generating the private key that will be used for domain certificates
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://tools.ietf.org/html/rfc3280#section-4.2.1.2
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	_, err = h.Write(pkixpub)
	if err != nil {
		return nil, err
	}
	keyID := h.Sum(nil)

	if storage == nil {
		storage = &CertsCache{certsCache: make(map[string]*tls.Certificate)}
	}

	return &Config{
		ca:           ca,
		caPrivateKey: privateKey,
		privateKey:   priv,
		keyID:        keyID,
		validity:     time.Hour,
		organization: "gomitmproxy",
		certsStorage: storage,
		roots:        roots,
	}, nil
}

// GetCA returns the authority cert
func (c *Config) GetCA() *x509.Certificate {
	return c.ca
}

// SetOrganization sets the organization name that
// will be used in generated certs
func (c *Config) SetOrganization(organization string) {
	c.organization = organization
}

// SetValidity sets validity period for the generated certs
func (c *Config) SetValidity(validity time.Duration) {
	c.validity = validity
}

// NewTLSConfigForHost creates a *tls.Config that will generate
// domain certificates on-the-fly using the SNI extension (if specified)
// or the hostname
func (c *Config) NewTLSConfigForHost(hostname string) *tls.Config {
	tlsConfig := &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := clientHello.ServerName
			if host == "" {
				host = hostname
			}

			return c.GetOrCreateCert(host)
		},
		NextProtos: []string{"http/1.1"},
	}

	// Accept client certs without verifying them
	// Note that we will still verify remote server certs
	// nolint:gosec
	tlsConfig.InsecureSkipVerify = true

	return tlsConfig
}

// GetOrCreateCert gets or creates a certificate for the specified hostname
func (c *Config) GetOrCreateCert(hostname string) (*tls.Certificate, error) {
	// Remove the port if it exists.
	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}

	c.certsStorageMu.RLock()
	tlsCertificate, ok := c.certsStorage.Get(hostname)
	c.certsStorageMu.RUnlock()

	if ok {
		log.Debug("mitm: cache hit for %s", hostname)

		// Check validity of the certificate for hostname match, expiry, etc. In
		// particular, if the cached certificate has expired, create a new one.
		if _, err := tlsCertificate.Leaf.Verify(x509.VerifyOptions{
			DNSName: hostname,
			Roots:   c.roots,
		}); err == nil {
			return tlsCertificate, nil
		}

		log.Debug("mitm: invalid certificate in the cache for %s", hostname)
	}

	log.Debug("mitm: cache miss for %s", hostname)

	// Increment the serial number
	serial := atomic.AddInt64(&currentSerialNumber, 1)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{c.organization},
		},
		SubjectKeyId:          c.keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-c.validity),
		NotAfter:              time.Now().Add(c.validity),
	}

	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, c.privateKey.Public(), c.caPrivateKey)
	if err != nil {
		return nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	tlsCertificate = &tls.Certificate{
		Certificate: [][]byte{raw, c.ca.Raw},
		PrivateKey:  c.privateKey,
		Leaf:        x509c,
	}

	c.certsStorageMu.Lock()
	c.certsStorage.Set(hostname, tlsCertificate)
	c.certsStorageMu.Unlock()
	return tlsCertificate, nil
}
