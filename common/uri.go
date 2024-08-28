package common

import (
	"net/url"
	"strings"

	"github.com/devopsext/utils"
)

type URI struct {
	Scheme   string
	UserName string
	Password string
	Host     string
	Port     string
	Path     string
	Query    string
	Fragment string
}

const (
	URISchemeUnknown = ""
	URISchemeHttp    = "http"
	URISchemeHttps   = "https"
)

const (
	URIPortUnknown = ""
	URIPortHttp    = "80"
	URIPortHttps   = "443"
)

// https://en.wikipedia.org/wiki/Uniform_Resource_Identifier
func URIParse(uri string) (*URI, error) {

	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	scheme := u.Scheme
	if utils.IsEmpty(scheme) {
		scheme = URISchemeHttps
	}
	scheme = strings.ToLower(scheme)

	port := u.Port()
	if utils.IsEmpty(port) {
		switch u.Scheme {
		case URIPortHttp:
			port = URIPortHttp
		case URISchemeHttps:
			port = URIPortHttps
		default:
			port = URIPortHttps
		}
	}

	userName := ""
	password := ""
	if u.User != nil {
		userName = u.User.Username()
		pwd, ok := u.User.Password()
		if ok {
			password = pwd
		}
	}

	r := URI{
		Scheme:   scheme,
		UserName: userName,
		Password: password,
		Host:     u.Host,
		Port:     port,
		Path:     u.Path,
		Query:    u.RawQuery,
		Fragment: u.Fragment,
	}

	return &r, nil
}

func URIScheme(uri string) string {

	u, err := URIParse(uri)
	if err != nil {
		return ""
	}
	return u.Scheme
}
