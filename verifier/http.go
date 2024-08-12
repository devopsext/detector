package verifier

import (
	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type HttpOptions struct {
	URL string
}

type Http struct {
	options HttpOptions
	logger  sreCommon.Logger
}

func (h *Http) Verify([]*common.ObserverResult) error {

	return nil
}

func NewHttp(options HttpOptions, observability *common.Observability) *Http {

	logger := observability.Logs()
	if utils.IsEmpty(options.URL) {
		logger.Debug("Http url is not defined. Skipped.")
		return nil
	}

	return &Http{
		options: options,
		logger:  logger,
	}
}
