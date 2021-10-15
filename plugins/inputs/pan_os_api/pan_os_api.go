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
<<<<<<< Updated upstream
	APIVersion      int64           `toml:"api_version"`
=======
>>>>>>> Stashed changes
	ResponseTimeout config.Duration `toml:"response_timeout"`
	APIkey          string          `toml:"api_key"`
	Interfaces      []string        `toml:"interfaces"`
	tls.ClientConfig

	client *http.Client
}

<<<<<<< Updated upstream
=======
const (
	// Commands
	systemInfoCmd            = "<show><system><info></info></system></show>"
	interfaceCounters        = "<show><interface>_if_</interface></show>"
	resourceMonitorPerSecond = "<show><running><resource-monitor><second></second></resource-monitor></running></show>"
)

>>>>>>> Stashed changes
var sampleConfig = `
  ## An array of API URI to gather stats.
  urls = ["http://firewall/api"]
  
  # HTTP response timeout (default: 5s)
  response_timeout = "5s"

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = false
`

func (n *PanOsAPI) SampleConfig() string {
	return sampleConfig
}

func (n *PanOsAPI) Description() string {
	return "PAN-OS API plugin"
}

func (n *PanOsAPI) Gather(acc telegraf.Accumulator) error {
	var wg sync.WaitGroup

	// Create an HTTP client that is re-used for each
	// collection interval

	if n.client == nil {
		client, err := n.createHTTPClient()
		if err != nil {
			return err
		}
		n.client = client
	}

	for _, u := range n.Urls {
		addr, err := url.Parse(u)
		if err != nil {
			acc.AddError(fmt.Errorf("unable to parse address '%s': %s", u, err))
			continue
		}

		wg.Add(1)
		go func(addr *url.URL) {
			defer wg.Done()
			n.gatherMetrics(addr, acc)
		}(addr)
	}

	wg.Wait()
	return nil
}

func (n *PanOsAPI) createHTTPClient() (*http.Client, error) {
	if n.ResponseTimeout < config.Duration(time.Second) {
		n.ResponseTimeout = config.Duration(time.Second * 5)
	}

	tlsConfig, err := n.ClientConfig.TLSConfig()
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: time.Duration(n.ResponseTimeout),
	}

	return client, nil
}

func init() {
	inputs.Add("pan_os_api", func() telegraf.Input {
		return &PanOsAPI{}
	})
}
