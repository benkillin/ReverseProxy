package main

import (
	"crypto/tls"
	"crypto/x509"
	//	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	// "golang.org/x/net/http2" // ooohhhhh fancy!

	log "github.com/sirupsen/logrus"

	"github.com/benkillin/ConfigHelper"
)

// Config represents the application's configuration
type Config struct {
	ListenPort string
	ListenHost string
	ListenTLS  *TLSProperties // optional - may be null

	Backends map[string]UpstreamHostConfig
}

// TLSProperties defines properties such as certificate and key for the cert and key file to use and whether or not mutually authenticated TLS is to be used and if so the different attributes that are necessary to be defined for mutually authenticated TLS.
type TLSProperties struct {
	Insecure             bool // if true, allow insecure TLS connection to the back-end.
	CertPath             string
	KeyPath              string
	TrustedCAs           string // path to trusted CA list of root CAs to use when this program is verifying the certificate presented by a backend server.
	MutualAuth           bool
	MutualAuthCAListFile string
	RevocationListCheck  bool
	RevocationListFile   string
	OCSPCheck            bool
	OCSPProvider         string
	STSHttpHeader        bool        // do we add strict transport security header to stuff served by this server (ignored on tls config for communicating with backend hosts)
	StrongTLS            bool        // "perfect ssl labs score?" see https://gist.github.com/denji/12b3a568f092ab951456
	CustomTLSConfig      *tls.Config // If this is set, all the other options are ignored.
}

// UpstreamHostConfig configuraiton options for the back end host that this reverse proxy is serving requests for it contains settings such as TLS trust settings, hostname, port, and any other necessary configuration information
type UpstreamHostConfig struct {
	HostPool ServerPool
}

// ServerPool represents a pool of servers with a selection strategy for routing the next request
type ServerPool struct {
	Hosts                       []Host
	PoolMemberSelectionStrategy string
}

// Host represents a back end host with a particular configuration for TLS
type Host struct {
	Hostname  string
	TLSConfig *TLSProperties // optional
	transport *http.Transport
}

func (p *ServerPool) nextHost() string {
	// TODO: have a variety of selection strategies available for this.
	return p.Hosts[0].Hostname
}

func main() {
	configFile := "reverseConfig.json"
	ROUND_ROBIN := "round-robin" // TODO: enum or something plz?

	defaultConfig := &Config{
		ListenHost: "",
		ListenPort: "8080",
		Backends: map[string]UpstreamHostConfig{
			"/path1": UpstreamHostConfig{ServerPool{[]Host{Host{"https://google.com:443/", nil, nil}}, ROUND_ROBIN}},
			"/path2": UpstreamHostConfig{ServerPool{[]Host{Host{"https://localhost:8443/", nil, nil}}, ROUND_ROBIN}},
			"/path3": UpstreamHostConfig{ServerPool{[]Host{Host{"https://localhost:9443/", nil, nil}}, ROUND_ROBIN}},
			"/path4": UpstreamHostConfig{ServerPool{[]Host{Host{"https://localhost:10443/", nil, nil}}, ROUND_ROBIN}},
		}}

	upstreamProxies := make(map[string]map[string]*(httputil.ReverseProxy))

	config := &Config{}

	ConfigHelper.GetConfigWithDefault(configFile, defaultConfig, config)

	// Need to setup an override to the transport.
	defaultTransport := http.DefaultTransport.(*http.Transport)

	// Create new Transport that ignores self-signed SSL
	/*insecureDefaultTransport := &http.Transport{
		Proxy:                 defaultTransport.Proxy,
		DialContext:           defaultTransport.DialContext,
		MaxIdleConns:          defaultTransport.MaxIdleConns,
		IdleConnTimeout:       defaultTransport.IdleConnTimeout,
		ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
		TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}*/

	for path, hostConfig := range config.Backends {
		log.Debugf("%s %v", path, hostConfig)

		// TODO: handle setting up multiple possible back-ends for a particular request path
		// TODO: find the howto article about making your own proxy configuration instead
		// of setting up multiple single host proxies
		proxies := make(map[string]*(httputil.ReverseProxy))

		for _, host := range hostConfig.HostPool.Hosts {
			remote, err := url.Parse(host.Hostname)
			if err != nil {
				log.Fatalf("Error: unable to parse host %v: %s", host, err)
			}
			proxy := httputil.NewSingleHostReverseProxy(remote)
			customTransport := *defaultTransport // ignore lint error about copying the mutex.

			if host.TLSConfig != nil {
				config, err := host.TLSConfig.GetTLSConfig()
				if err != nil {
					log.Fatalf("Error: unable to convert TLSConfig to tls.Config: %s", err)
				}

				customTransport.TLSClientConfig = config
				proxy.Transport = &customTransport
			} else {
				proxy.Transport = defaultTransport
			}

			proxies[host.Hostname] = proxy
		}

		upstreamProxies[path] = proxies
	}

	// The reason we set up the single host proxies above and then have a handle func that
	// finds the correct single host proxy for the URI prefix is so we can support having optional scripting
	// or custom handlers for various requests in the future, which would be defined as part of the backend
	// config. Also, it is set up like this so that we can use custom host selection strategies in the case
	// the back end is configured to have more than one upstream host.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		found := false
		requestedPath := r.URL.Path

		for path, host := range config.Backends {
			if strings.HasPrefix(requestedPath, path) {
				pool := upstreamProxies[path]

				nextUpstream := host.HostPool.nextHost()

				pool[nextUpstream].ServeHTTP(w, r)
				log.Printf("Serving request for %s (path %s) using host %v.", requestedPath, path, host)
				found = true
				break
			}
		}

		if !found {
			log.Printf("Received request for %s (client %s) which is not configured for a back end host.", requestedPath, r.RemoteAddr)
		}

	})

	// Start the server
	listenAddr := config.ListenHost + ":" + config.ListenPort

	if config.ListenTLS != nil {
		// TODO: support specifying advanced TLS options such as tls version and cipher suites.
		// see https://stackoverflow.com/questions/31226131/how-to-set-tls-cipher-for-go-server
		http.ListenAndServeTLS(listenAddr, config.ListenTLS.CertPath, config.ListenTLS.KeyPath, nil)
	} else {
		http.ListenAndServe(listenAddr, nil)
	}

}

func loadCertPool(file string) (*x509.CertPool, error) {
	trustedCAsForBackend, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Error reading certificate pool file (%s): %s", file, err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(trustedCAsForBackend) {
		return nil, fmt.Errorf("Unable to load x509 cert pool with certificate data from file '%s'", file)
	}
	return caPool, nil
}

// GetTLSConfig Converts TLSProperties to tls.Config
// see https://gist.github.com/michaljemala/d6f4e01c4834bf47a9c4
// see https://gist.github.com/denji/12b3a568f092ab951456
// see https://github.com/jomoespe/go-tls-mutual-auth/blob/master/server/server.go
func (tlsConfig *TLSProperties) GetTLSConfig() (*tls.Config, error) {
	if tlsConfig != nil {

		config := &tls.Config{}

		if tlsConfig.CustomTLSConfig != nil {
			return tlsConfig.CustomTLSConfig, nil
		}

		if tlsConfig.CertPath != "" && tlsConfig.KeyPath != "" {
			// the cert this program will use to authenticate with the backend:
			hostBasedClientCert, err := tls.LoadX509KeyPair(tlsConfig.CertPath, tlsConfig.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("Error loading certificate for tls.Config: %s", err)
			}
			config.Certificates = []tls.Certificate{hostBasedClientCert}
		} else {
			return nil, fmt.Errorf("Certificate keypair not specified")
		}

		if !tlsConfig.Insecure && tlsConfig.TrustedCAs != "" {
			// the list of CAs to trust for verifying the certificate the backend server sends this program:
			caPool, err := loadCertPool(tlsConfig.TrustedCAs)
			if err != nil {
				return nil, fmt.Errorf("unable to load trusted CAs: %s", err)
			}
			config.RootCAs = caPool
		}

		if tlsConfig.MutualAuth {
			if tlsConfig.MutualAuthCAListFile != "" {
				caPool, err := loadCertPool(tlsConfig.MutualAuthCAListFile)
				if err != nil {
					return nil, fmt.Errorf("unable to load mutual auth CAs: %s", err)
				}
				config.ClientCAs = caPool
			} // TODO: do we care if they specify mutual auth but dont set up a trust store for clients?

			if tlsConfig.Insecure {
				config.ClientAuth = tls.RequireAnyClientCert
			} else {
				config.ClientAuth = tls.RequireAndVerifyClientCert
			}
			// TODO:
			//tls.NoClientCert
			//tls.RequestClientCert
			//tls.RequireAnyClientCert
			//tls.VerifyClientCertIfGiven
		}

		// TODO: CRL and OCSP check handling

		if tlsConfig.StrongTLS {
			config.MinVersion = tls.VersionTLS12
			config.CurvePreferences = []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256}
			config.PreferServerCipherSuites = true
			config.CipherSuites = []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			}
		}

		config.BuildNameToCertificate()

		if tlsConfig.Insecure {
			config.InsecureSkipVerify = true
		}

		return config, nil

	}

	return nil, fmt.Errorf("Attempted to convert nil TLSProperties to tls.Config")
}
