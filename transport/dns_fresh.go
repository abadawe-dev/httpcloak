package transport

import "net/url"

// dnsHost is the name a new connection to connectHost resolves through the
// transport's DNS cache: the proxy's when there is one, else connectHost's own.
// Each request a transport sends keeps it fresh (dns.Cache.KeepFresh), so that
// the connection a dead one or a burst needs is never held on the resolver. A
// proxy URL that does not parse has no name to keep: its dial fails, saying
// why.
func dnsHost(proxy *ProxyConfig, connectHost string) (string, bool) {
	if proxy == nil || proxy.URL == "" {
		return connectHost, true
	}
	u, err := url.Parse(proxy.URL)
	if err != nil {
		return "", false
	}
	return u.Hostname(), true
}
