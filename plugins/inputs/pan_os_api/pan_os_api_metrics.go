package pan_os_api

import (
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/influxdata/telegraf"
)

func Match(pattern, name string) (matched bool) {
	if pattern == "" {
		return name == pattern
	}
	if pattern == "*" {
		return true
	}
	return deepMatchRune([]rune(name), []rune(pattern), false)
}

func deepMatchRune(str, pattern []rune, simple bool) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		case '?':
			if len(str) == 0 && !simple {
				return false
			}
		case '*':
			return deepMatchRune(str, pattern[1:], simple) ||
				(len(str) > 0 && deepMatchRune(str[1:], pattern, simple))
		}
		str = str[1:]
		pattern = pattern[1:]
	}
	return len(str) == 0 && len(pattern) == 0
}

func convertDate(date string) string {
	// convert date returned by PAN-OS API to RFC3339

	// set date layout for conversion
	dateLayout := "2006/01/02 15:04:05 MST"
	// todo fix error handling
	t, _ := time.Parse(dateLayout, date)

	// todo maybe output date format should be user selectable?
	return t.Format(time.RFC3339)
}

func (p *PanOsAPI) gatherMetrics(addr *url.URL, acc telegraf.Accumulator) {
	if len(p.IntervalSlow) > 0 {
		// long interval data collection
		if uint32(time.Since(p.lastT).Seconds()) >= p.scanIntervalSlow {
			if p.GatherUpdateStatus {
				// get dynamic updates status
				p.gatherUpdateStatus(addr, acc)
			}
			if p.GatherInterface {
				// update device interface table
				p.gatherInterfaces(addr)
			}
			p.lastT = time.Now()
		}
	}

	if p.GatherInterface {
		p.gatherInterfaceMetrics(addr, acc)
	}

	if p.GatherResource {
		p.gatherResourceMetrics(addr, acc)
	}

	if p.GatherVpnState {
		p.gatherVpnFlow(addr, acc)
	}
}

func (p *PanOsAPI) gatherURL(addr *url.URL, typ string, cmd string) ([]byte, error) {
	// parse target device URLs from configuration
	url := fmt.Sprintf("%s/api/?type=%s&cmd=%s&key=%s", addr.String(), typ, cmd, p.APIkey)
	resp, err := p.client.Get(url)

	if err != nil {
		return nil, fmt.Errorf("error making HTTP request to %s: %s", url, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("%s returned HTTP status %s", url, resp.Status)
	}

	contentType := strings.Split(resp.Header.Get("Content-Type"), ";")[0]
	switch contentType {
	case "application/xml":
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		return body, nil
	default:
		return nil, fmt.Errorf("%s returned unexpected content type %s", url, contentType)
	}
}

func (p *PanOsAPI) gatherHostname(addr *url.URL, acc telegraf.Accumulator) error {
	const typ = "op"
	body, err := p.gatherURL(addr, typ, showSystemInfo)
	if err != nil {
		return err
	}

	var response = &Response{}

	if err := xml.Unmarshal(body, response); err != nil {
		return err
	}

	acc.AddFields(
		"pan_os_api_hostname",
		map[string]interface{}{
			"hostname": response.Result.System.Hostname,
		},
		getTags(addr),
	)
	return nil
}

func (p *PanOsAPI) gatherUpdateStatus(addr *url.URL, acc telegraf.Accumulator) error {
	// reports PAN-OS Anti-Virus, App and Threat signature versions and release dates
	const typ = "op"
	body, err := p.gatherURL(addr, typ, showSystemInfo)
	if err != nil {
		return err
	}

	var response = &Response{}

	// parse XML
	if err := xml.Unmarshal(body, response); err != nil {
		return err
	}

	acc.AddFields(
		"pan_os_api_update",
		map[string]interface{}{
			"app-version":         response.Result.System.AppVersion,
			"app-release-date":    convertDate(response.Result.System.AppRelease),
			"av-version":          response.Result.System.AVVersion,
			"av-release-date":     convertDate(response.Result.System.AVRelease),
			"threat-version":      response.Result.System.ThreatVersion,
			"threat-release-date": convertDate(response.Result.System.ThreatRelease),
		},
		getTags(addr),
	)
	return nil
}

func (p *PanOsAPI) gatherVpnFlow(addr *url.URL, acc telegraf.Accumulator) error {
	// VPN flow status
	const typ = "op"
	body, err := p.gatherURL(addr, typ, showVpnFlow)
	if err != nil {
		return err
	}

	var response = &Response{}

	// parse XML
	if err := xml.Unmarshal(body, response); err != nil {
		return err
	}

	vpnEntries := response.Result.IPSec.Entry

	for _, vpn := range vpnEntries {
		acc.AddFields(
			"pan_os_api_vpnflow",
			map[string]interface{}{
				"vpn-tunnel-name":  vpn.Name,
				"vpn-tunnel-id":    vpn.Id,
				"vpn-tunnel-state": vpn.State,
			},
			getTags(addr),
		)
	}
	return nil
}

func (p *PanOsAPI) gatherInterfaces(addr *url.URL) error {
	// get list of all interfaces in target device
	body, err := p.gatherURL(addr, "op", "<show><interface>all</interface></show>")
	if err != nil {
		return err
	}

	var response = &Response{}
	if err := xml.Unmarshal(body, response); err != nil {
		return err
	}

	ifnets := response.Result.Interface.Entry
	p.deviceInts = make([]string, len(ifnets))

	// go through all reported cores
	for i, ifnet := range ifnets {
		p.deviceInts[i] = ifnet.Name
	}
	return nil
}

func (p *PanOsAPI) gatherInterfaceMetrics(addr *url.URL, acc telegraf.Accumulator) error {
	// interface counters
	const typ = "op"

	// go through all reported cores
	for _, ifnet := range p.deviceInts {
		for _, ifmatch := range p.Interfaces {
			if Match(ifmatch, ifnet) {
				cmd := strings.Replace(showInterface, "_if_", ifnet, 1)
				body, err := p.gatherURL(addr, typ, cmd)
				if err != nil {
					return err
				}

				var response = &Response{}

				// parse XML
				if err := xml.Unmarshal(body, response); err != nil {
					return err
				}

				acc.AddFields(
					"pan_os_api_interface",
					map[string]interface{}{
						"interface":   ifnet,
						"in-bytes":    response.Result.Interface.Counters.Interface.Entry.InBytes,
						"in-drops":    response.Result.Interface.Counters.Interface.Entry.InDrops,
						"in-errors":   response.Result.Interface.Counters.Interface.Entry.InErrors,
						"in-packets":  response.Result.Interface.Counters.Interface.Entry.InPackets,
						"out-bytes":   response.Result.Interface.Counters.Interface.Entry.OutBytes,
						"out-packets": response.Result.Interface.Counters.Interface.Entry.OutPackets,
					},
					getTags(addr),
				)
			}
		}
	}
	return nil
}

func (p *PanOsAPI) gatherResourceMetrics(addr *url.URL, acc telegraf.Accumulator) error {
	// resource metrics
	const typ = "op"

	body, err := p.gatherURL(addr, typ, showResourceMonitor)
	if err != nil {
		return err
	}

	var response = &Response{}

	// parse XML
	if err := xml.Unmarshal(body, response); err != nil {
		return err
	}

	cores := response.Result.ResourceMonitor.DataProcessors.Dp0.Second.CpuLoadAverage.Entry

	// go through all reported cores
	for coreId, entry := range cores {
		value := strings.Split(entry.Value, ",")

		var coreUtil = make([]int, len(value))

		for sec, i := range value {
			p, err := strconv.Atoi(i)
			if err != nil {
				panic(err)
			}
			coreUtil[sec] = p
		}

		var sum int
		// calculate average core utilization over set period
		// todo make this user configurable?
		var period int = 10

		for i := 0; i < period; i++ {
			sum += coreUtil[i]
		}
		avgUtil := sum / period

		acc.AddFields(
			"pan_os_api_resource",
			map[string]interface{}{
				"core":        coreId,
				"utilization": avgUtil,
			},
			getTags(addr),
		)
	}
	return nil
}

func getTags(addr *url.URL) map[string]string {
	h := addr.Host
	host, port, err := net.SplitHostPort(h)
	if err != nil {
		host = addr.Host
		// todo what other common tags should be included?
	}
	return map[string]string{"source": host, "port": port}
}
