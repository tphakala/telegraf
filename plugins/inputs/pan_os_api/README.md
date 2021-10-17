# Palo Alto Networks PAN-OS XML API input plugin

Collects metrics from Palo Alto Networks firewalls XML API. Plugin has been tested with VM-Series firewalls running PAN-OS 9.1 and newer releases.

Beware that some metrics collections can be very resource intensive for firewall management plane, interface metrics in particular if you have hunders of interfaces and include all of them in collection.

Plugin authenticates to PAN-OS XML API by API key which you need to request from firewall. Please use account with read-only role for API access. Instructions for how to request API key is at https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key.html

### Configuration

```toml
[[inputs.pan_os_api]]
  ## An array of firewalls to gather stats.
  urls = ["https://firewall"]
  
  ## API key used for authenticating to XML API
  api_key = ""

  ## Array if interfaces of which metrics should be collected, supports * and ? wildcards.
  ## Inventory of device interfaces is updated at regular interval defined by slow_interval
  ## parameter
  interfaces_include = ["ethernet1/?", "tunnel*"]

  ## Array if interfaces which should be excluded from metrics collection, supports * and ?
  interfaces_exclude = ["loopback", "vxlan"]
  
  ## Gather interface metrics
  ## - High impact for FW management plane
  gather_interface_metrics = true

  ## Gather resource metrics (dataplane CPU load)
  ## - Low impact for FW management plane
  gather_resource_metrics = true

  ## Gather dynamic updates status (threat, app, av update versions & release dates)
  ## Dynamic updates status collection interval is defined by interval_slow parameter
  ## - Low impact for FW management plane
  gather_update_status = false

  ## Gather IPSec VPN tunnel states (init, active)
  ## - Low impact for FW management plane
  gather_vpn_state = false
  
  ## Some tasks may be done at slower rate, these include
  ## - Dynamic update status collection
  ## - Inventory update of device interfaces to include or exclude from collection
  interval_slow = "5m"

  ## HTTP response timeout (default: 5s)
  response_timeout = "5s"

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = false
  ```
