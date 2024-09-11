package common

import (
	"maps"
	"slices"
	"strconv"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type NotifierProbability = float64

type NotifyResult struct {
	Notifier     Notifier
	VerifyResult *VerifyResult
}

type Notifier interface {
	Name() string
	Notify(vr *VerifyResult) (*NotifyResult, error)
}

type Notifiers struct {
	logger sreCommon.Logger
	items  []Notifier
}

type NotifierConfiguration struct {
	Notifier    Notifier
	Probability NotifierProbability
}

func (ns *Notifiers) Add(n Notifier) {

	if utils.IsEmpty(n) {
		return
	}
	ns.items = append(ns.items, n)
}

func (ns *Notifiers) Items() []Notifier {
	return ns.items
}

func (ns *Notifiers) GetDefaultConfigurations() []*NotifierConfiguration {

	r := []*NotifierConfiguration{}

	for _, n := range ns.items {
		r = append(r, &NotifierConfiguration{
			Notifier: n,
		})
	}
	return r
}

func (ns *Notifiers) FindConfigurationByPattern(pattern string) []*NotifierConfiguration {

	r := []*NotifierConfiguration{}

	if len(ns.items) == 0 {
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

	for _, v := range ns.items {

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
			ns.logger.Debug("Notifier cannot parse float %s for %s", sf, name)
			continue
		}

		r = append(r, &NotifierConfiguration{
			Notifier:    v,
			Probability: f,
		})
	}
	return r
}

func NewNotifiers(observability *Observability) *Notifiers {

	return &Notifiers{
		logger: observability.Logs(),
	}
}
