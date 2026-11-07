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
)
