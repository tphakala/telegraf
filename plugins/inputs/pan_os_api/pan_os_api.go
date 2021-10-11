package pan_os_api

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/plugins/common/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
)

type PanOsAPI struct {
	Urls            []string        `toml:"urls"`
	APIkey          string          `toml:"api_key"`
	ResponseTimeout config.Duration `toml:"response_timeout"`
	tls.ClientConfig

	client *http.Client
}

const (
	// Commands
	systemInfoCmd = "<show><system><info></info></system></show>"
)

var sampleConfig = `
  ## An array of API URI to gather stats.
  urls = ["http://firewall/api"]

  ## API key
  ## https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key.html
  api_key = ""
  
  # HTTP response timeout (default: 5s)
  response_timeout = "5s"

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = false
`

func (p *PanOsAPI) SampleConfig() string {
	return sampleConfig
}

func (p *PanOsAPI) Description() string {
	return "PAN-OS API plugin"
}

func (p *PanOsAPI) Gather(acc telegraf.Accumulator) error {
	var wg sync.WaitGroup

	// Create an HTTP client that is re-used for each
	// collection interval

	if p.client == nil {
		client, err := p.createHTTPClient()
		if err != nil {
			return err
		}
		p.client = client
	}

	for _, u := range p.Urls {
		addr, err := url.Parse(u)
		if err != nil {
			acc.AddError(fmt.Errorf("unable to parse address '%s': %s", u, err))
			continue
		}

		wg.Add(1)
		go func(addr *url.URL) {
			defer wg.Done()
			p.gatherMetrics(addr, acc)
		}(addr)
	}

	wg.Wait()
	return nil
}

func (p *PanOsAPI) createHTTPClient() (*http.Client, error) {
	if p.ResponseTimeout < config.Duration(time.Second) {
		p.ResponseTimeout = config.Duration(time.Second * 5)
	}

	tlsConfig, err := p.ClientConfig.TLSConfig()
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: time.Duration(p.ResponseTimeout),
	}

	return client, nil
}

func init() {
	inputs.Add("pan_os_api", func() telegraf.Input {
		return &PanOsAPI{}
	})
}
