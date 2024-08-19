package observer

import (
	"errors"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type DatadogOptions struct {
	URL string
	Key string
}

type Datadog struct {
	options *DatadogOptions
	logger  sreCommon.Logger
}

const ObserverDatadogName = "Datadog"

func (d *Datadog) Name() string {
	return ObserverDatadogName
}

func (d *Datadog) Observe(sr *common.SourceResult) (*common.ObserveResult, error) {

	if len(sr.Endpoints) == 0 {
		return nil, errors.New("Datadog cannot process empty endpoints")
	}

	es := []*common.Endpoint{}
	//  for

	r := &common.ObserveResult{
		Observer:     d,
		SourceResult: sr,
		Ednpoints:    es,
	}

	return r, nil
}

func NewDatadog(options *DatadogOptions, observability *common.Observability) *Datadog {

	logger := observability.Logs()
	if utils.IsEmpty(options.URL) {
		logger.Debug("Datdog url is not defined. Skipped.")
		return nil
	}

	return &Datadog{
		options: options,
		logger:  logger,
	}
}
