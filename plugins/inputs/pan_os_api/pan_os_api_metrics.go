package pan_os_api

import (
	"encoding/xml"
	"errors"
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

var (
	// errNotFound signals that the PAN-OS API routes does not exist.
	errNotFound = errors.New("not found")
)

func (p *PanOsAPI) gatherMetrics(addr *url.URL, acc telegraf.Accumulator) {
	addError(acc, p.gatherSignatureDetails(addr, acc))
	addError(acc, p.gatherInterfaceCounters(addr, acc))
	addError(acc, p.gatherCoreLoad(addr, acc))
}

func addError(acc telegraf.Accumulator, err error) {
	// This plugin has hardcoded API resource paths it checks that may not
	// be in the nginx.conf.  Currently, this is to prevent logging of
	// paths that are not configured.
	//
	// The correct solution is to do a GET to /api to get the available paths
	// on the server rather than simply ignore.
	if err != errNotFound {
		acc.AddError(err)
	}
}

// convert date returned by PAN-OS API to RFC3339
func convertDate(date string) string {
	// set date layout for conversion
	dateLayout := "2006/01/02 15:04:05 MST"
	// todo fix error handling
	t, _ := time.Parse(dateLayout, date)

	// todo maybe output date format should be user selectable?
	return t.Format(time.RFC3339)
}

// parse target device URLs from configurtion
func (p *PanOsAPI) gatherURL(addr *url.URL, typ string, cmd string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/?type=%s&cmd=%s&key=%s", addr.String(), typ, cmd, p.APIkey)
	resp, err := p.client.Get(url)

	if err != nil {
		return nil, fmt.Errorf("error making HTTP request to %s: %s", url, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// format as special error to catch and ignore as some nginx API
		// features are either optional, or only available in some versions
		return nil, errNotFound
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
	body, err := p.gatherURL(addr, typ, systemInfoCmd)
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

// reports PAN-OS Anti-Virus, App and Threat signature versions and release dates
func (p *PanOsAPI) gatherSignatureDetails(addr *url.URL, acc telegraf.Accumulator) error {
	const typ = "op"
	body, err := p.gatherURL(addr, typ, systemInfoCmd)
	if err != nil {
		return err
	}

	var response = &Response{}

	// parse XML
	if err := xml.Unmarshal(body, response); err != nil {
		return err
	}

	acc.AddFields(
		"pan_os_api_signatures",
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

// interface counters
func (p *PanOsAPI) gatherInterfaceCounters(addr *url.URL, acc telegraf.Accumulator) error {
	const typ = "op"

	// loop through interfaces
	for _, i := range p.Interfaces {

		cmd := strings.Replace(interfaceCounters, "_if_", i, 1)
		//body, err := p.gatherURL(addr, typ, interfaceCounters)
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
				"interface":   i,
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
	return nil
}

// resource monitor
func (p *PanOsAPI) gatherCoreLoad(addr *url.URL, acc telegraf.Accumulator) error {
	const typ = "op"

	body, err := p.gatherURL(addr, typ, resourceMonitorPerSecond)
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
			"pan_os_api_utilization",
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
