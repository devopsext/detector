package common

import (
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type Notifier interface {
	Notify([]*VerifierResult) error
}

type Notifiers struct {
	logger sreCommon.Logger
	items  []Notifier
}

func (ns *Notifiers) Add(n Notifier) {

	if utils.IsEmpty(n) {
		return
	}
	ns.items = append(ns.items, n)
}

func NewNotifiers(observability *Observability) *Notifiers {

	return &Notifiers{
		logger: observability.Logs(),
	}
}
