package pan_os_api

import (
	"errors"
	"net/url"

	"github.com/influxdata/telegraf"
)

var (
	// errNotFound signals that the PAN-OS API routes does not exist.
	errNotFound = errors.New("not found")
)

func (n *PanOsAPI) gatherMetrics(addr *url.URL, acc telegraf.Accumulator) {

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
