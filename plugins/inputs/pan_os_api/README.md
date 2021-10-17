# Palo Alto Networks PAN-OS input plugin

Collects metrics from Palo Alto Networks PAN-OS devices such as Strata firewalls and Panorama management server

### Configuration:

```## An array of firewalls to gather stats.
  urls = ["https://firewall"]
  
  ## Array if interfaces of which metrics should be collected, supports * and ? wildcards
  interfaces_include = ["ethernet1/?", "tunnel*"]

  ## Array if interfaces which should be excluded from metrics collection, supports * and ?
  interfaces_exclude = ["loopback", "vxlan"]
  
  ## Gather interface metrics
  gather_interface_metrics = true

  ## Gather resource metrics (dataplane CPU load etc)
  gather_resource_metrics = true

  ## Gather dynamic updates status (threat, app, av update versions & release dates)
  gather_update_status = false

  ## Gather IPSec VPN tunnel states (init, active)
  gather_vpn_state = false
  
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
  ```
