package oci

import (
	"net/http"

	"github.com/hashicorp/go-cleanhttp"
)

type userAgentTransporter struct {
	ua string
	rt http.RoundTripper
}

type Option = func(*http.Client)

func (u *userAgentTransporter) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", u.ua)

	return u.rt.RoundTrip(req)
}

func HttpTransport() http.RoundTripper {
	return &userAgentTransporter{
		ua: "Docker-Client",
		rt: cleanhttp.DefaultTransport(),
	}
}
