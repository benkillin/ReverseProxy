package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

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
	TLSCertPath             string
	TLSKeyPath              string
	TLSMutualAuth           bool
	TLSMutualAuthCAListFile string
	TLSRevocationListCheck  bool
	TLSRevocationListFile   string
	TLSOCSPCheck            bool
	TLSOCSPProvider         string
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
}

func (p *ServerPool) nextHost() string {
	// TODO: have a variety of selection strategies available for this.
	return p.Hosts[0].Hostname
}

func main() {
	configFile := "reverseConfig.json"
	ROUND_ROBIN := "round-robin" // TODO: enum or something plz?

	defaultConfig := &Config{
		ListenPort: ":8080",
		Backends: map[string]UpstreamHostConfig{
			"/path1": UpstreamHostConfig{ServerPool{[]Host{Host{"https://google.com:443/", nil}}, ROUND_ROBIN}},
			"/path2": UpstreamHostConfig{ServerPool{[]Host{Host{"https://localhost:8443/", nil}}, ROUND_ROBIN}},
			"/path3": UpstreamHostConfig{ServerPool{[]Host{Host{"https://localhost:9443/", nil}}, ROUND_ROBIN}},
			"/path4": UpstreamHostConfig{ServerPool{[]Host{Host{"https://localhost:10443/", nil}}, ROUND_ROBIN}},
		}}

	upstreamProxies := make(map[string]map[string]*(httputil.ReverseProxy))

	config := &Config{}

	ConfigHelper.GetConfigWithDefault(configFile, defaultConfig, config)

	// Need to setup an override to the transport.
	defaultTransport := http.DefaultTransport.(*http.Transport)

	// Create new Transport that ignores self-signed SSL
	httpClientWithSelfSignedTLS := &http.Transport{
		Proxy:                 defaultTransport.Proxy,
		DialContext:           defaultTransport.DialContext,
		MaxIdleConns:          defaultTransport.MaxIdleConns,
		IdleConnTimeout:       defaultTransport.IdleConnTimeout,
		ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
		TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	for path, hostConfig := range config.Backends {
		log.Printf("%s %s", path, hostConfig)

		// TODO: handle setting up multiple possible back-ends for a particular request path
		// TODO: find the howto article about making your own proxy configuration instead
		// of setting up multiple single host proxies
		proxies := make(map[string]*(httputil.ReverseProxy))

		for _, host := range hostConfig.HostPool.Hosts {
			remote, err := url.Parse(host.Hostname)
			if err != nil {
				log.Fatalf("Error: unable to parse host %s: %s", host, err)
			}
			proxy := httputil.NewSingleHostReverseProxy(remote)

			proxy.Transport = httpClientWithSelfSignedTLS // TODO: handle setting up THE SHIZNIT to handle custom TLS options.
		}

		upstreamProxies[path] = proxies
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		found := false
		requestedPath := r.URL.Path

		for path, host := range config.Backends {
			if strings.HasPrefix(requestedPath, path) {
				pool := upstreamProxies[path]

				nextUpstream := host.HostPool.nextHost()

				pool[nextUpstream].ServeHTTP(w, r)
				log.Printf("Serving request for %s (path %s) using host %s.", requestedPath, path, host)
				found = true
				break
			}
		}

		if !found {
			log.Printf("Received request for %s (client %s) which is not configured for a back end host.", requestedPath, r.RemoteAddr)
		}

	})

	// Start the server
	http.ListenAndServe(config.ListenPort, nil)
}
