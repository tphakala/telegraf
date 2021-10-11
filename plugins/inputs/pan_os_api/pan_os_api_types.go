package pan_os_api

import "encoding/xml"

type Response struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Result  Result   `xml:"result"`
}

type Result struct {
	XMLName      xml.Name `xml:"result"`
	System       System   `xml:"system"`
	Cps          string   `xml:"cps"`           // connections per second
	Pps          string   `xml:"pps"`           // packets per second
	NumMax       string   `xml:"num-max"`       // maximum sessions supported by system
	NumActive    string   `xml:"num-active"`    // active session count
	NumTcp       string   `xml:"num-tcp"`       // TCP session count
	NumUdp       string   `xml:"num-udp"`       // UDP session count
	NumIcmp      string   `xml:"num-icmp"`      // ICMP session count
	NumBcast     string   `xml:"num-bcast"`     // Broadcast session count
	NumMcast     string   `xml:"num-mcast"`     // Multicast session count
	NumInstalled string   `xml:"num-installed"` // unknown

}

type System struct {
	XMLName          xml.Name       `xml:"system"`
	Hostname         string         `xml:"hostname"`
	IPAddress        string         `xml:"ip-address"`
	MACAddress       string         `xml:"mac-address"`
	Uptime           string         `xml:"uptime"`
	DeviceName       string         `xml:"devicename"`
	Model            string         `xml:"model"`
	Serial           string         `xml:"serial"`
	SWVersion        string         `xml:"sw-version"`
	GPClientVer      string         `xml:"global-protect-client-package-version"`
	DevDictVer       string         `xml:"device-dictionary-version"`
	DevDictRel       string         `xml:"device-dictionary-release-date"`
	AppVer           string         `xml:"app-version"`
	AppRel           string         `xml:"app-release-date"`
	AVVer            string         `xml:"av-version"`
	AVRel            string         `xml:"av-release-date"`
	ThreatVer        string         `xml:"threat-version"`
	ThreatRel        string         `xml:"threat-release-date"`
	UrlVer           string         `xml:"url-filtering-version"`
	PluginVersions   PluginVersions `xml:"plugin_versions"`
	MultiVsys        string         `xml:"multi-vsys"`
	OperationalMode  string         `xml:"operational-mode"`
	DeviceCertStatus string         `xml:"device-certificate-status"`
}

type PluginVersions struct {
	XMLName        xml.Name `xml:"plugin_versions"`
	PluginVersions []Entry  `xml:"entry"`
}

type Entry struct {
	XMLName xml.Name `xml:"entry"`
	Name    string   `xml:"name"`
	Version string   `xml:"version"`
	Pkginfo Pkginfo  `xml:"pkginfo"`
}

type Pkginfo struct {
	XMLName xml.Name `xml:"pkginfo"`
	Pkginfo string   `xml:"pkginfo"`
}
