package notifier

import (
	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	vendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type SlackOptions struct {
	vendors.SlackOptions
}

type Slack struct {
	options SlackOptions
	logger  sreCommon.Logger
	client  *vendors.Slack
}

const NotifierSlackName = "Slack"

func (s *Slack) Name() string {
	return NotifierSlackName
}

func (s *Slack) Notify(vr *common.VerifyResult) (*common.NotifyResult, error) {

	opts := vendors.SlackMessageOptions{
		Title: "hey",
		Text:  "<@U06ASAW1RMY> app billing",
	}
	_, err := s.client.SendMessage(opts)
	if err != nil {
		return nil, err
	}

	return nil, nil
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
		client:  vendors.NewSlack(options.SlackOptions),
	}
}
