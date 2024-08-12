package notifier

import (
	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type SlackOptions struct {
	Token string
}

type Slack struct {
	options SlackOptions
	logger  sreCommon.Logger
}

func (s *Slack) Notify([]*common.VerifierResult) error {

	return nil
}

func NewSlack(options SlackOptions, observability *common.Observability) *Slack {

	logger := observability.Logs()
	if utils.IsEmpty(options.Token) {
		logger.Debug("Slack token is not defined. Skipped.")
		return nil
	}

	return &Slack{
		options: options,
		logger:  logger,
	}
}
