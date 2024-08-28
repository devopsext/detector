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
	options *HttpOptions
	logger  sreCommon.Logger
}

const HttpVerifierName = "Config"

func (h *Http) Name() string {
	return HttpVerifierName
}

func (h *Http) Verify(or *common.ObserveResult) (*common.VerifyResult, error) {

	return nil, nil
}

func NewHttp(options *HttpOptions, observability *common.Observability) *Http {

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
