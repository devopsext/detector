package common

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type ObserveProbability = float64
type ObserveCountries = map[string]*ObserveProbability

type ObserveEndpoint struct {
	URI       string
	Countries ObserveCountries
	IPs       []string
	Response  *SourceEndpointResponse
}

type ObserveEndpoints struct {
	items []*ObserveEndpoint
}

type ObserverConfiguration struct {
	Observer    Observer
	Probability ObserveProbability
}

type ObserveResult struct {
	Configuration *ObserverConfiguration
	Endpoints     ObserveEndpoints
}

type Observer interface {
	Name() string
	Observe(sr *SourceResult) (*ObserveResult, error)
}

type Observers struct {
	logger sreCommon.Logger
	items  []Observer
}

// ObserveEndpoints

func (oes *ObserveEndpoints) Clone(oe *ObserveEndpoint) *ObserveEndpoint {

	oc := make(ObserveCountries)
	for k, v := range oe.Countries {

		var p ObserveProbability
		if v != nil {
			p = *v
		}
		oc[k] = &p
	}

	new := &ObserveEndpoint{
		URI:       oe.URI,
		Countries: oc,
		IPs:       oe.IPs,
		Response:  oe.Response,
	}
	return new
}

func (oes *ObserveEndpoints) Add(e ...*ObserveEndpoint) {
	oes.items = append(oes.items, e...)
}

func (oes *ObserveEndpoints) Items() []*ObserveEndpoint {
	return oes.items
}

func (oes *ObserveEndpoints) IsEmpty() bool {
	return len(oes.items) == 0
}

func (oes *ObserveEndpoints) Reduce() ObserveEndpoints {

	// find same URIs
	uris := make(map[string][]*ObserveEndpoint)
	for _, ep := range oes.items {

		if ep == nil {
			continue
		}

		uri := NormalizeURI(ep.URI)
		items := uris[uri]
		if items == nil {
			items = []*ObserveEndpoint{}
		}
		items = append(items, ep)
		uris[uri] = items
	}

	r := ObserveEndpoints{}

	// calculate avg per uri
	for uri, items := range uris {

		// group by country, add ips, gather responses
		countries := make(map[string][]*ObserveProbability)
		ips := []string{}
		responses := []*SourceEndpointResponse{}

		for _, item := range items {

			for k, v := range item.Countries {

				if v == nil {
					continue
				}
				k := NormalizeCountry(k)
				values := countries[k]
				countries[k] = append(values, v)
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

		// calculate avg per country
		ecountries := make(ObserveCountries)
		for k, values := range countries {

			sum := float64(0.0)
			count := 0
			for _, v := range values {

				if v == nil {
					continue
				}
				sum = sum + *v
				count++
			}

			if count == 0 {
				continue
			}

			v := sum / float64(count)
			ecountries[k] = &v
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

		ep := &ObserveEndpoint{
			URI:       uri,
			Countries: ecountries,
			IPs:       ips,
			Response:  response,
		}
		r.Add(ep)
	}

	return r
}

// Observers

func (ob *Observers) Add(o Observer) {

	if utils.IsEmpty(o) {
		return
	}
	ob.items = append(ob.items, o)
}

func (ob *Observers) Items() []Observer {
	return ob.items
}

func (ob *Observers) GetDefaultConfigurations() []*ObserverConfiguration {

	r := []*ObserverConfiguration{}

	for _, o := range ob.items {
		r = append(r, &ObserverConfiguration{
			Observer: o,
		})
	}
	return r
}

func (ob *Observers) FindConfigurationByPattern(pattern string) []*ObserverConfiguration {

	r := []*ObserverConfiguration{}

	if len(ob.items) == 0 {
		return r
	}

	if utils.IsEmpty(pattern) {
		return r
	}

	m := utils.MapGetKeyValuesEx(pattern, ";", ":")
	if len(m) == 0 {
		return r
	}
	keys := slices.Collect(maps.Keys(m))

	for _, o := range ob.items {

		name := o.Name()
		if !utils.Contains(keys, name) {
			continue
		}

		sf := m[name]
		if utils.IsEmpty(sf) {
			continue
		}
		f, err := strconv.ParseFloat(sf, 64)
		if err != nil {
			ob.logger.Debug("Observers cannot parse float %s for %s", sf, name)
			continue
		}

		r = append(r, &ObserverConfiguration{
			Observer:    o,
			Probability: f,
		})
	}
	return r
}

func NewObservers(observability *Observability) *Observers {

	return &Observers{
		logger: observability.Logs(),
	}
}
