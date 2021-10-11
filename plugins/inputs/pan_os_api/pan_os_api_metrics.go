package pan_os_api

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/influxdata/telegraf"
)

var (
	// errNotFound signals that the PAN-OS API routes does not exist.
	errNotFound = errors.New("not found")
)

func (p *PanOsAPI) gatherMetrics(addr *url.URL, acc telegraf.Accumulator) {
	addError(acc, p.gatherHostname(addr, acc))
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

func getTags(addr *url.URL) map[string]string {
	h := addr.Host
	host, port, err := net.SplitHostPort(h)
	if err != nil {
		host = addr.Host
		if addr.Scheme == "http" {
			port = "80"
		} else if addr.Scheme == "https" {
			port = "443"
		} else {
			port = ""
		}
	}
	return map[string]string{"source": host, "port": port}
}
