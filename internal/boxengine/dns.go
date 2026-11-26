package boxengine

var (
	DefaultBootstrapDNS = []string{
		"223.5.5.5:53",
		"119.29.29.29:53",
	}
	DefaultDomesticDoH = []string{
		"https://223.5.5.5/dns-query",
		"https://1.12.12.12/dns-query",
	}
	DefaultRemoteDoH = []string{
		"https://1.1.1.1/dns-query",
		"https://dns.google/dns-query",
	}
	DefaultBootstrapDoH = DefaultDomesticDoH

	DefaultBootstrapDNSV6 = []string{
		"[2400:3200::1]:53",
		"[2402:4e00::]:53",
	}
	DefaultDomesticDoHV6 = []string{
		"https://[2400:3200::1]/dns-query",
		"https://[2402:4e00::]/dns-query",
	}
	DefaultRemoteDoHV6 = []string{
		"https://[2606:4700:4700::1111]/dns-query",
		"https://[2001:4860:4860::8888]/dns-query",
	}
)
