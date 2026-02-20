package detector

import (
	"context"
	"fmt"
	"sync"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

// ProcessOptions holds configuration for the Process detector.
type ProcessOptions struct {
	Name                   string
	Schedule               string
	Countries              []string
	Triggers               *common.Triggers
	Sources                []common.Source
	ObserverConfigurations []*common.ObserverConfiguration
	VerifierConfigurations []*common.VerifierConfiguration
	NotifierConfigurations []*common.NotifierConfiguration
}

// Process is a detector that monitors business processes.
// Logic is a stub — full implementation to be done later.
type Process struct {
	options *ProcessOptions
	logger  sreCommon.Logger
	lock    *sync.Mutex
}

const ProcessDetectorName = "Process"

func (p *Process) Name() string {
	name := p.options.Name
	if utils.IsEmpty(name) {
		name = ProcessDetectorName
	}
	return name
}

func (p *Process) Schedule() string {
	return p.options.Schedule
}

// Start initialises sources for this detector.
func (p *Process) Start(ctx context.Context) {
	for _, s := range p.options.Sources {
		if err := s.Start(ctx); err != nil {
			p.logger.Error("Process %s detector source start error: %s", p.Name(), err)
		}
	}
}

// Detect is a stub. Full detection logic will be implemented later.
func (p *Process) Detect() error {
	if !p.lock.TryLock() {
		return fmt.Errorf("Process %s detector already in a loop", p.Name())
	}
	defer p.lock.Unlock()

	p.logger.Debug("Process %s detector is running (stub)", p.Name())
	return nil
}

func NewProcess(options *ProcessOptions, observability *common.Observability) *Process {

	logger := observability.Logs()

	if utils.IsEmpty(options.Sources) {
		logger.Debug("Process detector has no sources. Skipped")
		return nil
	}

	return &Process{
		options: options,
		logger:  logger,
		lock:    &sync.Mutex{},
	}
}
