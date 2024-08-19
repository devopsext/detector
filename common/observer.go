package common

import (
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type ObserveResult struct {
	Observer     Observer
	SourceResult *SourceResult
	Ednpoints    Endpoints
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

func NewObservers(observability *Observability) *Observers {

	return &Observers{
		logger: observability.Logs(),
	}
}
