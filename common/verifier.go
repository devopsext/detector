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
	URI             string
	Countries       VerifyCountries
	ObserveEndpoint *ObserveEndpoint
}

type VerifyEndpoints = []*VerifyEndpoint

type VerifyResult struct {
	Verifier      Verifier
	ObserveResult *ObserveResult
	Endpoints     VerifyEndpoints
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

func (vs *Verifiers) Add(v Verifier) {

	if utils.IsEmpty(v) {
		return
	}
	vs.items = append(vs.items, v)
}

func (vs *Verifiers) Items() []Verifier {
	return vs.items
}

func (vs *Verifiers) FindConfigurationByPattern(pattern string) map[string]*VerifierConfiguration {

	r := make(map[string]*VerifierConfiguration)

	if len(vs.items) == 0 {
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

		r[name] = &VerifierConfiguration{
			Verifier:    v,
			Probability: f,
		}
	}
	return r
}

func NewVerifiers(observability *Observability) *Verifiers {

	return &Verifiers{
		logger: observability.Logs(),
	}
}
