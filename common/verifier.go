package common

import (
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type VerifierResult struct {
	Results []*ObserverResult
}

type Verifier interface {
	Verify([]*ObserverResult) error
}

type Verifiers struct {
	logger    sreCommon.Logger
	items     []Verifier
	notifiers *Notifiers
}

func (vs *Verifiers) Add(v Verifier) {

	if utils.IsEmpty(v) {
		return
	}
	vs.items = append(vs.items, v)
}

func NewVerifiers(observability *Observability, notifiers *Notifiers) *Verifiers {

	return &Verifiers{
		logger:    observability.Logs(),
		notifiers: notifiers,
	}
}
