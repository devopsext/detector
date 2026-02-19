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

type ObserveItem struct {
	Key       string `json:"key,omitempty"` // primary key (значение DataDog тега, домен и т.д.)
	Countries ObserveCountries
	IPs       []string
	Response  *SourceItemResponse
}

type ObserveItems struct {
	items []ObserveEntry
}

type ObserverConfiguration struct {
	Observer    Observer
	Probability ObserveProbability
}

type ObserveResult struct {
	Configuration *ObserverConfiguration
	Items         ObserveItems
}

type Observer interface {
	Name() string
	Observe(sr *SourceResult) (*ObserveResult, error)
}

type Observers struct {
	logger sreCommon.Logger
	items  []Observer
}

// ObserveItem implements ObserveEntry

func (oi *ObserveItem) EntryKey() string {
	return oi.Key
}

func (oi *ObserveItem) EntryIdent() string                      { return oi.EntryKey() }
func (oi *ObserveItem) EntryObserveCountries() ObserveCountries { return oi.Countries }

// Compile-time check that *ObserveItem implements ObserveEntry.
var _ ObserveEntry = (*ObserveItem)(nil)

// ObserveItems

func (oes *ObserveItems) Clone(oi *ObserveItem) *ObserveItem {

	oc := make(ObserveCountries)
	for k, v := range oi.Countries {

		var p ObserveProbability
		if v != nil {
			p = *v
		}
		oc[k] = &p
	}

	return &ObserveItem{
		Key:       oi.Key,
		Countries: oc,
		IPs:       oi.IPs,
		Response:  oi.Response,
	}
}

func (oes *ObserveItems) Add(e ...ObserveEntry) {
	oes.items = append(oes.items, e...)
}

func (oes *ObserveItems) Items() []ObserveEntry {
	return oes.items
}

func (oes *ObserveItems) IsEmpty() bool {
	return len(oes.items) == 0
}

func (oes *ObserveItems) Reduce() ObserveItems {

	// group by EntryKey
	groups := make(map[string][]ObserveEntry)
	for _, entry := range oes.items {
		if entry == nil {
			continue
		}
		k := entry.EntryKey()
		groups[k] = append(groups[k], entry)
	}

	r := ObserveItems{}

	for key, items := range groups {

		countries := make(map[string][]*ObserveProbability)
		ips := []string{}
		responses := []*SourceItemResponse{}

		for _, item := range items {

			for k, v := range item.EntryObserveCountries() {
				if v == nil {
					continue
				}
				nc := NormalizeCountry(k)
				countries[nc] = append(countries[nc], v)
			}

			if ep, ok := item.(*ObserveItem); ok {
				for _, ip := range ep.IPs {
					if utils.Contains(ips, ip) {
						continue
					}
					ips = append(ips, ip)
				}
				if ep.Response != nil {
					responses = append(responses, ep.Response)
				}
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
		var response *SourceItemResponse
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

			response = &SourceItemResponse{
				Code:    code,
				Content: content,
			}
		}

		ep := &ObserveItem{
			Key:       key,
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

		name := strings.ToLower(o.Name())

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
