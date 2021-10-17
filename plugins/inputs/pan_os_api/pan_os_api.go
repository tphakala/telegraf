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
	Urls                 []string        `toml:"urls"`
	ResponseTimeout      config.Duration `toml:"response_timeout"`
	APIkey               string          `toml:"api_key"`
	InterfaceIncludeList []string        `toml:"interfaces_include"`
	InterfaceExcludeList []string        `toml:"interfaces_exclude"`
	GatherUpdateStatus   bool            `toml:"gather_update_status"`
	GatherResource       bool            `toml:"gather_resource_metrics"`
	GatherInterface      bool            `toml:"gather_interface_metrics"`
	GatherVpnState       bool            `toml:"gather_vpn_state"`
	IntervalSlow         string          `toml:"interval_slow"`
	tls.ClientConfig

	client             *http.Client
	lastT              time.Time
	scanIntervalSlow   uint32
	includedInterfaces []string
}

const (
	// Commands
	showSystemInfo      = "<show><system><info></info></system></show>"
	showInterface       = "<show><interface>_if_</interface></show>"
	showResourceMonitor = "<show><running><resource-monitor><second></second></resource-monitor></running></show>"
	showVpnFlow         = "<show><vpn><flow></flow></vpn></show>"
	showBgpPeer         = "<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>"
	showCounterGlobal   = "<show><counter><global></global></counter></show>"
)

var sampleConfig = `
  ## An array of API URI to gather stats.
  urls = ["http://firewall/api"]
  
  ## Array if interfaces of which metrics should be collected
  interface = ["ethernet1/1", "ethernet1/2"]

  ## Gather interface metrics
  gather_interface_metrics = true

  ## Gather resource metrics (dataplane CPU load etc)
  gather_resource_metrics = true

  ## Gather dynamic updates status (threat, app, av update versions & release dates)
  gather_update_status = false

  ## Some queries we may want to run less often
  interval_slow = "1m"

  ## HTTP response timeout (default: 5s)
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
	return "PAN-OS API plugin for collecting metrics from Palo Alto Networks devices"
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

	// init long interval scanning
	if len(p.IntervalSlow) > 0 {
		interval, err := time.ParseDuration(p.IntervalSlow)
		if err == nil && interval.Seconds() >= 1.0 {
			p.scanIntervalSlow = uint32(interval.Seconds())
		}
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
