package common

import (
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type SourceResult struct {
	Endpoints []Endpoint
}

type Source interface {
	Load() error
}

type Sources struct {
	logger    sreCommon.Logger
	items     []Source
	observers *Observers
}

func (sc *Sources) Add(s Source) {

	if utils.IsEmpty(s) {
		return
	}
	sc.items = append(sc.items, s)
}

func NewSources(observability *Observability, observers *Observers) *Sources {

	return &Sources{
		logger:    observability.Logs(),
		observers: observers,
	}
}
