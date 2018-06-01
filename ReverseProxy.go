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
	HostPool                    []string
	PoolMemberSelectionStrategy string
}

func main() {
	configFile := "reverseConfig.json"

	defaultConfig := &Config{
		ListenPort: ":8080",
		Backends: map[string]UpstreamHostConfig{
			"/path1": UpstreamHostConfig{[]string{"https://localhost:7443/"}},
			"/path2": UpstreamHostConfig{[]string{"https://localhost:8443/"}},
			"/path3": UpstreamHostConfig{[]string{"https://localhost:9443/"}},
			"/path4": UpstreamHostConfig{[]string{"https://localhost:10443/"}},
		}}

	singleHostProxies := make(map[string]*(httputil.ReverseProxy))

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

	for path, host := range config.Backends {
		log.Println(path + " " + host.Host)

		remote, err := url.Parse(host.Host)
		if err != nil {
			log.Fatalf("Error: unable to parse host %s: %s", host, err)
		}
		proxy := httputil.NewSingleHostReverseProxy(remote)
		proxy.Transport = httpClientWithSelfSignedTLS

		singleHostProxies[path] = proxy
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		found := false
		requestedPath := r.URL.Path

		for path, host := range config.Backends {
			if strings.HasPrefix(requestedPath, path) {
				singleHostProxies[path].ServeHTTP(w, r)
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
