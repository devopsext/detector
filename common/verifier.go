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

type VerifyResult struct {
	Endpoints VerifyEndpoints
}

type Verifier interface {
	Name() string
	Verify(or *ObserveResult) (*VerifyResult, error)
}

type VerifierConfiguration struct {
	Verifier    Verifier
	Probability VerifyProbability
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

func (ves *VerifyEndpoints) FindByURI(uri string) *VerifyEndpoints {

	r := &VerifyEndpoints{}

	nURI := NormalizeURI(uri)
	if utils.IsEmpty(nURI) {
		return r
	}

	for _, ep := range ves.items {

		epURI := NormalizeURI(ep.URI)
		if nURI == epURI {
			r.Add(ep)
		}
	}
	return r
}

func (ves *VerifyEndpoints) Merge(eps *VerifyEndpoints) {

	if eps == nil {
		return
	}

	for _, ep := range eps.items {

		sameURIs := ves.FindByURI(ep.URI)
		if sameURIs.IsEmpty() {
			new := ves.Clone(ep)
			ves.Add(new)
			continue
		}

		// to do
		/*
			for _, _ := range sameURIs.items {

			}
		*/
	}
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
