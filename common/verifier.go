package common

import (
	"maps"
	"slices"
	"strconv"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type VerifyProbability = float64

type VerifyStatusFlag = string
type VerifyStatusFlags = map[VerifyStatusFlag]bool

const (
	VerifyStatusFlagWrongIPAddress    VerifyStatusFlag = "wrong_ip_address"
	VerifyStatusFlagWrongResponseCode VerifyStatusFlag = "wrong_response_code"
)

type VerifyStatus struct {
	Probability *VerifyProbability
	Flags       VerifyStatusFlags
}

type VerifyCountries = map[string]*VerifyStatus

type VerifyEndpoint struct {
	URI       string
	Countries VerifyCountries
}

type VerifyEndpoints struct {
	items []*VerifyEndpoint
}

type VerifierConfiguration struct {
	Verifier    Verifier
	Probability VerifyProbability
}

type VerifyResult struct {
	Configuration *VerifierConfiguration
	Endpoints     VerifyEndpoints
}

type Verifier interface {
	Name() string
	Verify(or *ObserveResult) (*VerifyResult, error)
}

type Verifiers struct {
	logger sreCommon.Logger
	items  []Verifier
}

// VerifyEndpoints

func (ves *VerifyEndpoints) Clone(ve *VerifyEndpoint) *VerifyEndpoint {

	vc := make(VerifyCountries)
	for k, v := range ve.Countries {

		vc[k] = &VerifyStatus{
			Probability: v.Probability,
			Flags:       v.Flags,
		}
	}

	new := &VerifyEndpoint{
		URI:       ve.URI,
		Countries: vc,
	}
	return new
}

func (ves *VerifyEndpoints) Add(e ...*VerifyEndpoint) {
	ves.items = append(ves.items, e...)
}

func (ves *VerifyEndpoints) Items() []*VerifyEndpoint {
	return ves.items
}

func (ves *VerifyEndpoints) IsEmpty() bool {
	return len(ves.items) == 0
}

func (ves *VerifyEndpoints) Reduce() VerifyEndpoints {

	// find same URIs
	uris := make(map[string][]*VerifyEndpoint)
	for _, ep := range ves.items {

		if ep == nil {
			continue
		}

		uri := NormalizeURI(ep.URI)
		items := uris[uri]
		if items == nil {
			items = []*VerifyEndpoint{}
		}
		items = append(items, ep)
		uris[uri] = items
	}

	r := VerifyEndpoints{}

	// calculate avg per uri
	for uri, items := range uris {

		// group by country, add ips, gather responses
		countries := make(map[string][]*VerifyStatus)

		for _, item := range items {

			for k, v := range item.Countries {

				if v == nil {
					continue
				}
				k := NormalizeCountry(k)
				values := countries[k]
				countries[k] = append(values, v)
			}
		}

		// calculate avg per country
		vcountries := make(VerifyCountries)
		for k, values := range countries {

			sum := float64(0.0)
			count := 0
			flags := make(map[VerifyStatusFlag]bool)

			for _, v := range values {

				if v == nil {
					continue
				}

				p := v.Probability
				if p == nil {
					continue
				}

				sum = sum + *p
				count++

				if len(v.Flags) == 0 {
					continue
				}

				for f, b := range v.Flags {

					if !b {
						continue
					}
					flags[f] = b
				}
			}

			if count == 0 {
				continue
			}

			v := sum / float64(count)
			vcountries[k] = &VerifyStatus{
				Probability: &v,
				Flags:       flags,
			}
		}

		ep := &VerifyEndpoint{
			URI:       uri,
			Countries: vcountries,
		}
		r.Add(ep)
	}

	return r
}

// Verifiers

func (vs *Verifiers) Add(v Verifier) {

	if utils.IsEmpty(v) {
		return
	}
	vs.items = append(vs.items, v)
}

func (vs *Verifiers) Items() []Verifier {
	return vs.items
}

func (vs *Verifiers) GetDefaultConfigurations() []*VerifierConfiguration {

	r := []*VerifierConfiguration{}

	for _, v := range vs.items {
		r = append(r, &VerifierConfiguration{
			Verifier: v,
		})
	}
	return r
}

func (vs *Verifiers) FindConfigurationByPattern(pattern string) []*VerifierConfiguration {

	r := []*VerifierConfiguration{}

	if len(vs.items) == 0 {
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

	for _, v := range vs.items {

		name := v.Name()
		if !utils.Contains(keys, name) {
			continue
		}

		sf := m[name]
		if utils.IsEmpty(sf) {
			continue
		}
		f, err := strconv.ParseFloat(sf, 64)
		if err != nil {
			vs.logger.Debug("Verifiers cannot parse float %s for %s", sf, name)
			continue
		}

		r = append(r, &VerifierConfiguration{
			Verifier:    v,
			Probability: f,
		})
	}
	return r
}

func NewVerifiers(observability *Observability) *Verifiers {

	return &Verifiers{
		logger: observability.Logs(),
	}
}
