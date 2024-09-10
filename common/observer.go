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
	URI            string
	Countries      ObserveCountries
	SourceEndpoint *SourceEndpoint
}

type ObserveEndpoints = []*ObserveEndpoint

type ObserveResult struct {
	Observer     Observer
	SourceResult *SourceResult
	Endpoints    ObserveEndpoints
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

	m := utils.MapGetKeyValues(pattern)
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
