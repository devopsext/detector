package observer

import (
	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type DatadogOptions struct {
	URL string
}

type Datadog struct {
	options *DatadogOptions
	logger  sreCommon.Logger
}

func (d *Datadog) Observe([]*common.Endpoint) error {

	return nil
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
