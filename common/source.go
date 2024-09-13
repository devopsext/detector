package common

import (
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type SourceEndpointResponse struct {
	Code    string `json:"code,omitempty"`
	Content string `json:"content,omitempty"`
}

type SourceEndpoint struct {
	URI       string                  `json:"uri"`
	Disabled  bool                    `json:"disabled"`
	Countries []string                `json:"countries,omitempty"`
	IPs       []string                `json:"ips,omitempty"`
	Detectors []string                `json:"detectors,omitempty"`
	Response  *SourceEndpointResponse `json:"response,omitempty"`
}

type SourceEndpoints struct {
	items []*SourceEndpoint
}

type SourceResult struct {
	Endpoints SourceEndpoints
}

type Source interface {
	Name() string
	Load() (*SourceResult, error)
}

type Sources struct {
	logger sreCommon.Logger
	items  []Source
}

// SourceEndpoints

func (ses *SourceEndpoints) Clone(se *SourceEndpoint) *SourceEndpoint {

	var r *SourceEndpointResponse
	if se.Response != nil {
		r = &SourceEndpointResponse{
			Code:    se.Response.Code,
			Content: se.Response.Content,
		}
	}

	new := &SourceEndpoint{
		URI:       se.URI,
		Disabled:  se.Disabled,
		Countries: se.Countries,
		IPs:       se.IPs,
		Detectors: se.Detectors,
		Response:  r,
	}
	return new
}

func (ses *SourceEndpoints) Add(e ...*SourceEndpoint) {
	ses.items = append(ses.items, e...)
}

func (ses *SourceEndpoints) Items() []*SourceEndpoint {
	return ses.items
}

func (ses *SourceEndpoints) IsEmpty() bool {
	return len(ses.items) == 0
}

func (ses *SourceEndpoints) FindByURI(uri string) *SourceEndpoints {

	r := &SourceEndpoints{}

	nURI := NormalizeURI(uri)
	if utils.IsEmpty(nURI) {
		return r
	}

	for _, ep := range ses.items {

		epURI := NormalizeURI(ep.URI)
		if nURI == epURI {
			r.Add(ep)
		}
	}
	return r
}

func (ses *SourceEndpoints) Merge(eps *SourceEndpoints) {

	if eps == nil {
		return
	}

	for _, ep := range eps.items {

		sameURIs := ses.FindByURI(ep.URI)
		if sameURIs.IsEmpty() {
			new := ses.Clone(ep)
			ses.Add(new)
			continue
		}

		epCountries := NormalizeCountries(ep.Countries)
		for _, e := range sameURIs.items {

			same := false
			if e.Response != nil && ep.Response != nil {
				same = e.Response.Code == ep.Response.Code && e.Response.Content == ep.Response.Content
			}

			if !same {
				continue
			}

			eCountries := NormalizeCountries(e.Countries)
			for _, c := range epCountries {
				if utils.Contains(eCountries, c) {
					continue
				}
				e.Countries = append(e.Countries, c)
			}

			for _, ip := range ep.IPs {
				if utils.Contains(e.IPs, ip) {
					continue
				}
				e.IPs = append(e.IPs, ip)
			}
		}
	}
}

// Sources

func (ss *Sources) Add(s Source) {

	if utils.IsEmpty(s) {
		return
	}
	ss.items = append(ss.items, s)
}

func (ss *Sources) Items() []Source {
	return ss.items
}

func (ss *Sources) FindByName(name string) Source {

	for _, s := range ss.items {

		if s.Name() == name {
			return s
		}
	}
	return nil
}

func NewSources(observability *Observability) *Sources {

	return &Sources{
		logger: observability.Logs(),
	}
}
