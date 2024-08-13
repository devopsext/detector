package detector

import (
	"errors"
	"sync"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
)

type AvailabilityOptions struct {
	Schedule string
}

type Availability struct {
	options   *AvailabilityOptions
	logger    sreCommon.Logger
	sources   *common.Sources
	observers *common.Observers
	verifiers *common.Verifiers
	notifiers *common.Notifiers
	lock      *sync.Mutex
}

const AvailabilityDetectorName = "Availability"

// Availability

func (a *Availability) Name() string {
	return AvailabilityDetectorName
}

func (a *Availability) Schedule() string {
	return a.options.Schedule
}

func (a *Availability) load() (*common.Endpoints, error) {

	items := a.sources.Items()
	if len(items) == 0 {
		return nil, errors.New("Availability detector cannot find source items")
	}

	r := common.Endpoints{}
	for _, s := range items {
		es, err := s.Load()
		if err != nil {
			return nil, err
		}
		r = append(r, es...)
	}
	return &r, nil
}

func (a *Availability) Detect() error {

	if !a.lock.TryLock() {
		return errors.New("Availability detector already in a loop")
	}
	defer a.lock.Unlock()

	endpoints, err := a.load()
	if err != nil {
		return err
	}
	a.logger.Debug("%v", endpoints)

	return nil
}

func NewAvailability(options *AvailabilityOptions, observability *common.Observability,
	sources *common.Sources, observers *common.Observers, verifiers *common.Verifiers, notifiers *common.Notifiers) *Availability {

	return &Availability{
		options:   options,
		logger:    observability.Logs(),
		sources:   sources,
		observers: observers,
		verifiers: verifiers,
		notifiers: notifiers,
		lock:      &sync.Mutex{},
	}
}
