package dhcpinfo

import (
	"context"
	"os/exec"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
)

func DNSServers(ctx context.Context) ([]netaddr.IP, error) {
	ifaces, err := interfaces.GetList()
	if err != nil {
		return nil, err
	}

	var ret []netaddr.IP
	for _, i := range ifaces {
		out, err := exec.CommandContext(ctx,
			"ipconfig",
			"getoption",
			i.Name,
			"domain_name_server",
		).CombinedOutput()
		if err != nil {
			// exit code 1 and no output means "no DNS server for this interface"
			if exerr, ok := err.(*exec.ExitError); ok {
				if exerr.ExitCode() == 1 && len(out) == 0 {
					continue
				}
			}
			return nil, err
		}
		s := strings.TrimSpace(string(out))
		if s == "" {
			continue
		}

		ip, err := netaddr.ParseIP(s)
		if err != nil {
			return nil, err
		}
		ret = append(ret, ip)
	}

	return ret, nil
}

/*

TODO: should use system APIs to get everything

>>> from SystemConfiguration import *
>>> prefs = SCPreferencesCreate(None, "foo", None)
>>> for service in SCNetworkServiceCopyAll(prefs):
...   if SCNetworkServiceGetName(service) == "Wi-Fi":
...     wifi_service = service
>>> wifi_interface = SCNetworkServiceGetInterface(wifi_service)
>>> print SCNetworkInterfaceGetBSDName(wifi_interface)
en0
>>> dynstore = SCDynamicStoreCreate(kCFAllocatorSystemDefault, "pytest", None, None)
>>> SCDynamicStoreCopyValue(dynstore, "State:/Network/Global/IPv4")
{
    PrimaryInterface = en0;
    PrimaryService = "159B4674-1585-4151-B03B-0803E93B721B";
    Router = "192.168.4.1";
}
>>> SCDynamicStoreCopyValue(dynstore, "State:/Network/Service/{}/DNS".format("159B4674-1585-4151-B03B-0803E93B721B"))
{
    ServerAddresses =     (
        "149.112.121.10",
        "149.112.122.10"
    );
}
>>> dnsinfo = SCDynamicStoreCopyValue(dynstore, "State:/Network/Service/{}/DNS".format("159B4674-1585-4151-B03B-0803E93B721B"))
>>> CFDictionaryGetValue(dnsinfo, "ServerAddresses")[0]
u'149.112.121.10'

*/
