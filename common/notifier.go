package common

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type NotifierProbability = float64

type Notifier interface {
	Name() string
	Notify(vr *VerifyResult) error
}

// NotifierDefault is the interface for notifiers that support the Default pipeline.
type NotifierDefault interface {
	Name() string
	NotifyDefault(vr *VerifyDefaultResult) error
}

type Notifiers struct {
	logger sreCommon.Logger
	items  []Notifier
}

type NotifierConfiguration struct {
	Notifier    Notifier
	Probability NotifierProbability
}

type NotifyDefaultTrackingItem struct {
	ItemIndex int
	MessageID string
}

// NotifierDefaultTrackable extends NotifierDefault with message tracking and status checking.
type NotifierDefaultTrackable interface {
	NotifierDefault
	NotifyDefaultWithTracking(vr *VerifyDefaultResult) ([]*NotifyDefaultTrackingItem, error)
	CheckMessageStatus(id string) (string, error)
}

// NotifierDefaultConfiguration wraps a NotifierDefault for use in the Default pipeline.
type NotifierDefaultConfiguration struct {
	Notifier         NotifierDefault
	ThresholdWarning float64
	ThresholdAlert   float64
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
