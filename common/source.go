package common

import (
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type Source interface {
	Name() string
	Load() (Endpoints, error)
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
