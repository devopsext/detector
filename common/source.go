package common

import (
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type SourceResult struct {
	Source    Source
	Endpoints Endpoints
}

type Source interface {
	Name() string
	Load() (*SourceResult, error)
}

type Sources struct {
	logger sreCommon.Logger
	items  []Source
}

func (ss *Sources) Add(s Source) {

	if utils.IsEmpty(s) {
		return
	}
	ss.items = append(ss.items, s)
}

func (ss *Sources) Items() []Source {
	return ss.items
}

func NewSources(observability *Observability) *Sources {

	return &Sources{
		logger: observability.Logs(),
	}
}
