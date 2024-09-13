package common

import (
	"maps"
	"slices"
	"strconv"

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

type ObserveResult struct {
	Endpoints ObserveEndpoints
}

type ObserverConfiguration struct {
	Observer    Observer
	Probability ObserveProbability
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

func (oes *ObserveEndpoints) FindByURI(uri string) *ObserveEndpoints {

	r := &ObserveEndpoints{}

	nURI := NormalizeURI(uri)
	if utils.IsEmpty(nURI) {
		return r
	}

	for _, ep := range oes.items {

		epURI := NormalizeURI(ep.URI)
		if nURI == epURI {
			r.Add(ep)
		}
	}
	return r
}

func (oes *ObserveEndpoints) Merge(eps *ObserveEndpoints) {

	if eps == nil {
		return
	}

	for _, ep := range eps.items {

		sameURIs := oes.FindByURI(ep.URI)
		if sameURIs.IsEmpty() {
			new := oes.Clone(ep)
			oes.Add(new)
			continue
		}

		// to do
		/*
			for _, _ := range sameURIs.items {

			}
		*/
	}
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
