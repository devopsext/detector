package detector

import (
	"context"
	"fmt"
	"sync"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

// ApplicationOptions holds configuration for the Application detector.
type ApplicationOptions struct {
	Name                   string
	Schedule               string
	Countries              []string
	Triggers               *common.Triggers
	Sources                []common.Source
	ObserverConfigurations []*common.ObserverConfiguration
	VerifierConfigurations []*common.VerifierConfiguration
	NotifierConfigurations []*common.NotifierConfiguration
}

// Application is a detector that monitors frontend applications.
// Logic is a stub — full implementation to be done later.
type Application struct {
	options *ApplicationOptions
	logger  sreCommon.Logger
	lock    *sync.Mutex
}

const ApplicationDetectorName = "Application"

func (a *Application) Name() string {
	name := a.options.Name
	if utils.IsEmpty(name) {
		name = ApplicationDetectorName
	}
	return name
}

func (a *Application) Schedule() string {
	return a.options.Schedule
}

// Start initialises sources for this detector.
func (a *Application) Start(ctx context.Context) {
	for _, s := range a.options.Sources {
		if err := s.Start(ctx); err != nil {
			a.logger.Error("Application %s detector source start error: %s", a.Name(), err)
		}
	}
}

// Detect is a stub. Full detection logic will be implemented later.
func (a *Application) Detect() error {
	if !a.lock.TryLock() {
		return fmt.Errorf("Application %s detector already in a loop", a.Name())
	}
	defer a.lock.Unlock()

	a.logger.Debug("Application %s detector is running (stub)", a.Name())
	return nil
}

func NewApplication(options *ApplicationOptions, observability *common.Observability) *Application {

	logger := observability.Logs()

	if utils.IsEmpty(options.Sources) {
		logger.Debug("Application detector has no sources. Skipped")
		return nil
	}

	return &Application{
		options: options,
		logger:  logger,
		lock:    &sync.Mutex{},
	}
}
