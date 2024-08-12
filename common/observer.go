package common

import (
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type ObserverResult struct {
	Results []*SourceResult
}

type Observer interface {
	Observe([]*SourceResult) error
}

type Observers struct {
	logger    sreCommon.Logger
	items     []Observer
	verifiers *Verifiers
}

func (ob *Observers) Add(o Observer) {

	if utils.IsEmpty(o) {
		return
	}
	ob.items = append(ob.items, o)
}

func NewObservers(observability *Observability, verifiers *Verifiers) *Observers {

	return &Observers{
		logger:    observability.Logs(),
		verifiers: verifiers,
	}
}
