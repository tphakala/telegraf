package pan_os_api

import "encoding/xml"

type Response struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	//	Result  Result   `xml:"result"`
	Result struct {
		XMLName         xml.Name        `xml:"result"`
		System          System          `xml:"system"`
		CPS             uint64          `xml:"cps"`                // connections per second
		PPS             uint64          `xml:"pps"`                // packets per second
		NumMax          uint64          `xml:"num-max"`            // maximum sessions supported by system
		NumActive       uint64          `xml:"num-active"`         // active session count
		NumTcp          uint64          `xml:"num-tcp"`            // TCP session count
		NumUdp          uint64          `xml:"num-udp"`            // UDP session count
		NumIcmp         uint64          `xml:"num-icmp"`           // ICMP session count
		NumBcast        uint64          `xml:"num-bcast"`          // Broadcast session count
		NumMcast        uint64          `xml:"num-mcast"`          // Multicast session count
		NumInstalled    uint64          `xml:"num-installed"`      // unknown
		GPCurUsers      uint64          `xml:"TotalCurrentUsers"`  // GlobalProtect Portal current users
		GPPrevUsers     uint64          `xml:"TotalPreviousUsers"` // GlobalProtect Portal previous(?) users
		Interface       Interface       `xml:"ifnet"`
		ResourceMonitor ResourceMonitor `xml:"resource-monitor"`
	}
}

type ResourceMonitor struct {
	XMLName        xml.Name `xml:"resource-monitor"`
	DataProcessors struct {
		XMLName xml.Name `xml:"data-processors"`
		Dp0     struct {
			XMLName xml.Name `xml:"dp0"`
			Second  Second   `xml:"second"`
		}
		Dp1 struct {
			XMLName xml.Name `xml:"dp1"`
			Second  Second   `xml:"second"`
		}
		Dp2 struct {
			XMLName xml.Name `xml:"dp2"`
			Second  Second   `xml:"second"`
		}
		Dp3 struct {
			XMLName xml.Name `xml:"dp3"`
			Second  Second   `xml:"second"`
		}
	}
}

// resource monitor values by second
type Second struct {
	XMLName             xml.Name            `xml:"second"`
	CpuLoadAverage      CpuLoadAverage      `xml:"cpu-load-average"`
	CpuLoadMaximum      CpuLoadMaximum      `xml:"cpu-load-maximum"`
	Task                Task                `xml:"task"`
	ResourceUtilization ResourceUtilization `xml:"resource-utilization"`
}

type CpuLoadAverage struct {
	XMLName xml.Name `xml:"cpu-load-average"`
	Entry   []Entry  `xml:"entry"`
}

type CpuLoadMaximum struct {
	XMLName xml.Name `xml:"cpu-load-maximum"`
	Entry   []Entry  `xml:"entry"`
}

type Task struct {
	XMLName xml.Name `xml:"task"`
}

type ResourceUtilization struct {
	XMLName xml.Name `xml:"resource-utilization"`
}

type System struct {
	XMLName        xml.Name `xml:"system"`
	Hostname       string   `xml:"hostname"`
	IPAddress      string   `xml:"ip-address"`
	MACAddress     string   `xml:"mac-address"`
	Uptime         string   `xml:"uptime"`
	DeviceName     string   `xml:"devicename"`
	Model          string   `xml:"model"`
	Serial         string   `xml:"serial"`
	SWVersion      string   `xml:"sw-version"`
	GPClientVer    string   `xml:"global-protect-client-package-version"`
	DevDictVersion string   `xml:"device-dictionary-version"`
	DevDictRelease string   `xml:"device-dictionary-release-date"`
	AppVersion     string   `xml:"app-version"`
	AppRelease     string   `xml:"app-release-date"`
	AVVersion      string   `xml:"av-version"`
	AVRelease      string   `xml:"av-release-date"`
	ThreatVersion  string   `xml:"threat-version"`
	ThreatRelease  string   `xml:"threat-release-date"`
	URLVersion     string   `xml:"url-filtering-version"`
	//PluginVersions   PluginVersions `xml:"plugin_versions"`
	MultiVsys        string `xml:"multi-vsys"`
	OperationalMode  string `xml:"operational-mode"`
	DeviceCertStatus string `xml:"device-certificate-status"`
}

type Interface struct {
	XMLName  xml.Name `xml:"ifnet"`
	Counters Counters `xml:"counters"`
	Hardware Hardware `xml:"hw"`
	Entry    []Entry  `xml:"entry"`
}

type Counters struct {
	XMLName xml.Name `xml:"counters"`
	//Interface Interface2 `xml:"ifnet"`
	Interface struct {
		XMLName xml.Name `xml:"ifnet"`
		Entry   Entry    `xml:"entry"`
	}
}

type Hardware struct {
	XMLName xml.Name `xml:"hw"`
	Entry   []Entry  `xml:"entry"`
}

type Port struct {
	XMLName     xml.Name `xml:"port"`
	TxUnicast   uint64   `xml:"tx-unicast"`
	TxMulticast uint64   `xml:"tx-multicast"`
	TxBroadcast uint64   `xml:"tx-broadcast"`
	TxBytes     uint64   `xml:"tx-bytes"`
	RxUnicast   uint64   `xml:"rx-unicast"`
	RxBroadcast uint64   `xml:"rx-broadcast"`
	RxMulticast uint64   `xml:"rx-multicast"`
	RxBytes     uint64   `xml:"rx-bytes"`
}

type Entry struct {
	XMLName     xml.Name `xml:"entry"`
	Name        string   `xml:"name"`
	ICMPFrag    uint64   `xml:"icmp_frag"`
	InFwdErrors uint64   `xml:"ifwderrors"`
	InErrors    uint64   `xml:"ierrors"`
	InBytes     uint64   `xml:"ibytes"`
	OutBytes    uint64   `xml:"obytes"`
	InPackets   uint64   `xml:"ipackets"`
	OutPackets  uint64   `xml:"opackets"`
	InDrops     uint64   `xml:"idrops"`
	Port        Port     `xml:"port"`
	CoreId      uint8    `xml:"coreid"`
	Value       string   `xml:"value"`

	//Version string   `xml:"version"`
	//Pkginfo Pkginfo  `xml:"pkginfo"`

}

/*
no tests for these for now

type PluginVersions struct {
	XMLName        xml.Name `xml:"plugin_versions"`
	PluginVersions []Entry  `xml:"entry"`
}



type Pkginfo struct {
	XMLName xml.Name `xml:"pkginfo"`
	Pkginfo string   `xml:"pkginfo"`
}
*/
