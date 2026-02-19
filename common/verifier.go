package common

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

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

type VerifyItem struct {
	Key       string `json:"key,omitempty"` // primary key
	URI       string `json:"uri,omitempty"` // backward compat for domains
	Countries VerifyCountries
}

type VerifyItems struct {
	items []VerifyEntry
}

type VerifierConfiguration struct {
	Verifier    Verifier
	Probability VerifyProbability
}

type VerifyResult struct {
	Configuration *VerifierConfiguration
	Items         VerifyItems
}

type Verifier interface {
	Name() string
	Verify(or *ObserveResult) (*VerifyResult, error)
}

type Verifiers struct {
	logger sreCommon.Logger
	items  []Verifier
}

// VerifyItem implements VerifyEntry

func (ve *VerifyItem) EntryKey() string {
	if ve.Key != "" {
		return ve.Key
	}
	return NormalizeURI(ve.URI)
}

// EntryIdent returns EntryKey() + " [sorted countries]" for trigger deduplication.
// Example: "domain.com [TH,US]", "deposit [BW,ZA]"
func (ve *VerifyItem) EntryIdent() string {
	keys := slices.Collect(maps.Keys(ve.Countries))
	if len(keys) == 0 {
		return ve.EntryKey()
	}
	slices.Sort(keys)
	return fmt.Sprintf("%s [%s]", ve.EntryKey(), strings.Join(keys, ","))
}

func (ve *VerifyItem) EntryVerifyCountries() VerifyCountries { return ve.Countries }

// Compile-time check that *VerifyItem implements VerifyEntry.
var _ VerifyEntry = (*VerifyItem)(nil)

// VerifyItems

func (ves *VerifyItems) Clone(ve *VerifyItem) *VerifyItem {

	vc := make(VerifyCountries)
	for k, v := range ve.Countries {
		vc[k] = &VerifyStatus{
			Probability: v.Probability,
			Flags:       v.Flags,
		}
	}

	return &VerifyItem{
		Key:       ve.Key,
		URI:       ve.URI,
		Countries: vc,
	}
}

func (ves *VerifyItems) Add(e ...VerifyEntry) {
	ves.items = append(ves.items, e...)
}

func (ves *VerifyItems) Items() []VerifyEntry {
	return ves.items
}

func (ves *VerifyItems) IsEmpty() bool {
	return len(ves.items) == 0
}

func (ves *VerifyItems) Reduce() VerifyItems {

	// group by EntryKey
	groups := make(map[string][]VerifyEntry)
	for _, entry := range ves.items {
		if entry == nil {
			continue
		}
		k := entry.EntryKey()
		groups[k] = append(groups[k], entry)
	}

	r := VerifyItems{}

	for key, items := range groups {

		countries := make(map[string][]*VerifyStatus)

		for _, item := range items {
			for k, v := range item.EntryVerifyCountries() {
				if v == nil {
					continue
				}
				nc := NormalizeCountry(k)
				countries[nc] = append(countries[nc], v)
			}
		}

		// calculate avg per country + merge flags
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

		ep := &VerifyItem{
			Key:       key,
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
		r = append(r, &VerifierConfiguration{Verifier: v})
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

		name := strings.ToLower(v.Name())

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
