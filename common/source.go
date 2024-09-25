package common

import (
	"strings"

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

func (ses *SourceEndpoints) Reduce() SourceEndpoints {

	// find same URIs
	uris := make(map[string][]*SourceEndpoint)
	for _, ep := range ses.items {

		if ep == nil {
			continue
		}

		uri := NormalizeURI(ep.URI)
		items := uris[uri]
		if items == nil {
			items = []*SourceEndpoint{}
		}
		items = append(items, ep)
		uris[uri] = items
	}

	r := SourceEndpoints{}

	for uri, items := range uris {

		// group by country, add ips, gather responses
		countries := []string{}
		ips := []string{}
		responses := []*SourceEndpointResponse{}

		for _, item := range items {

			for _, c := range item.Countries {

				if utils.Contains(countries, c) {
					continue
				}
				countries = append(countries, c)
			}

			for _, ip := range item.IPs {

				if utils.Contains(ips, ip) {
					continue
				}
				ips = append(ips, ip)
			}

			if item.Response != nil {
				responses = append(responses, item.Response)
			}
		}

		// build response
		var response *SourceEndpointResponse
		if len(responses) > 0 {

			codes := []string{}
			contents := []string{}

			for _, res := range responses {

				if !utils.IsEmpty(res.Code) && !utils.Contains(codes, res.Code) {
					codes = append(codes, res.Code)
				}
				if !utils.IsEmpty(res.Content) && !utils.Contains(contents, res.Content) {
					contents = append(contents, res.Content)
				}
			}

			code := ""
			if len(codes) != 0 {
				code = strings.Join(codes, "|")
			}

			content := ""
			if len(contents) != 0 {
				content = strings.Join(contents, "|")
			}

			response = &SourceEndpointResponse{
				Code:    code,
				Content: content,
			}
		}

		ep := &SourceEndpoint{
			URI:       uri,
			Countries: countries,
			IPs:       ips,
			Response:  response,
		}
		r.Add(ep)
	}
	return r
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
