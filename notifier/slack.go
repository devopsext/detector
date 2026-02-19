package notifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	vendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type SlackOptions struct {
	vendors.SlackOptions
	Channel  string
	Message  string
	Runbooks string
	Offset   time.Duration
}

type Slack struct {
	options  SlackOptions
	logger   sreCommon.Logger
	client   *vendors.Slack
	message  *toolsRender.TextTemplate
	runbooks *toolsRender.TextTemplate
	metrics  *common.VerifierMetrics
}

const NotifierSlackName = "Slack"

func (s *Slack) Name() string {
	return NotifierSlackName
}

func (s *Slack) renderTemplate(template *toolsRender.TextTemplate, vr *common.VerifyResult) ([]byte, error) {

	b, err := template.RenderObject(vr)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Slack) execute(mr *vendors.SlackMessageResponse, vr *common.VerifyResult) error {

	if s.runbooks == nil {
		return nil
	}

	d, err := s.renderTemplate(s.runbooks, vr)
	if err != nil {
		return err
	}

	items := strings.Split(string(d), "\n")

	for _, v := range items {

		vs := strings.TrimSpace(v)
		if utils.IsEmpty(vs) {
			continue
		}
		opts := vendors.SlackMessageOptions{
			Channel: mr.Channel,
			Thread:  mr.TS,
			Text:    v,
		}
		_, err = s.client.SendMessage(opts)
		if err != nil {
			s.logger.Error(err)
		}
	}
	return nil
}

func (s *Slack) Notify(vr *common.VerifyResult) error {

	if vr.Items.IsEmpty() {
		return errors.New("Slack notifier cannot process empty items")
	}

	s.logger.Debug("Slack notifier is processing...")

	// Record notification start in metrics - single API call for all notifications
	if s.metrics != nil {
		s.metrics.RecordTestStartByType("notifier", "slack", "slack_api", "all")
	}

	t1 := time.Now()

	d, err := s.renderTemplate(s.message, vr)
	if err != nil {
		// Record template rendering error in metrics
		if s.metrics != nil {
			s.metrics.RecordTestErrorByType("notifier", "slack", "slack_api", "all", "template_rendering_error", 0)
		}
		return err
	}

	sd := strings.TrimSpace(string(d))
	if utils.IsEmpty(sd) {
		return nil
	}

	opts := vendors.SlackMessageOptions{
		Channel: s.options.Channel,
		Text:    string(d),
	}
	r, err := s.client.SendMessage(opts)
	if err != nil {
		// Record message sending error in metrics
		if s.metrics != nil {
			s.metrics.RecordTestErrorByType("notifier", "slack", "slack_api", "all", "message_sending_error", 0)
		}
		return err
	}

	mr := vendors.SlackMessageResponse{}
	err = json.Unmarshal(r, &mr)
	if err != nil {
		// Record JSON unmarshal error in metrics
		if s.metrics != nil {
			s.metrics.RecordTestErrorByType("notifier", "slack", "slack_api", "all", "json_unmarshal_error", 0)
		}
		return err
	}

	err = s.execute(&mr, vr)
	if err != nil {
		s.message.LogError(err)
		// Record execution error in metrics
		if s.metrics != nil {
			s.metrics.RecordTestErrorByType("notifier", "slack", "slack_api", "all", "execution_error", 0)
		}
	}

	// Record successful notification in metrics
	if s.metrics != nil {
		s.metrics.RecordTestSuccessByType("notifier", "slack", "slack_api", "all", float64(time.Since(t1).Seconds()))
	}

	s.logger.Debug("Slack notifier spent %s", time.Since(t1))

	return nil
}

func (s *Slack) fIndirect(obj interface{}) interface{} {

	v1 := reflect.ValueOf(obj)
	v2 := reflect.Indirect(v1)
	return v2.Interface()
}

func (s *Slack) fGetConversationHistory() *vendors.GetConversationHistoryResponse {
	if s.client == nil {
		return nil
	}
	off := s.options.Offset
	if off == 0 {
		off = 1 // Default to 1 hour if not specified
	}
	offset := time.Now().Add(-time.Hour * off).Unix() // 1 hour ago

	params := vendors.GetConversationHistoryParameters{
		ChannelID: s.options.Channel,
		Limit:     100, // Slack recommends 100 as a reasonable page size
		Oldest:    fmt.Sprintf("%d", offset),
		Inclusive: true, // Include messages at the oldest timestamp
	}

	allMessages := &vendors.GetConversationHistoryResponse{}
	cursor := ""
	for {
		params.Cursor = cursor
		history, err := s.client.GetConversationHistory(params)
		if err != nil {
			s.logger.Error("Slack notifier get conversation history error: %s", err)
			break
		}
		h := &vendors.GetConversationHistoryResponse{}
		err = json.Unmarshal(history, h)
		if err != nil {
			s.logger.Error("Slack notifier get conversation history unmarshal error: %s", err)
			break
		}

		// Append messages to allMessages
		allMessages.Messages = append(allMessages.Messages, h.Messages...)

		// Check for next cursor
		if h.ResponseMetadata.NextCursor == "" {
			break
		}
		cursor = h.ResponseMetadata.NextCursor
	}

	return allMessages
}

func NewSlack(options SlackOptions, observability *common.Observability, metrics *common.VerifierMetrics) *Slack {

	logger := observability.Logs()

	if utils.IsEmpty(options.Token) {
		logger.Debug("Slack notifier token is not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.Message) {
		logger.Debug("Slack notifier message is not defined. Skipped.")
		return nil
	}

	r := &Slack{
		options: options,
		logger:  logger,
		metrics: metrics,
	}

	funcs := make(map[string]any)
	funcs["indirect"] = r.fIndirect
	funcs["getConversationHistory"] = r.fGetConversationHistory

	messageOpts := toolsRender.TemplateOptions{
		Content: options.Message,
		Funcs:   funcs,
	}
	message, err := toolsRender.NewTextTemplate(messageOpts, observability)
	if err != nil {
		logger.Error("Slack notifier message error: %s", err)
		return nil
	}

	runbooksOpts := toolsRender.TemplateOptions{
		Content: options.Runbooks,
		Funcs:   funcs,
	}
	runbooks, err := toolsRender.NewTextTemplate(runbooksOpts, observability)
	if err != nil {
		logger.Error("Slack notifier runbooks error: %s", err)
	}

	r.client = vendors.NewSlack(options.SlackOptions)
	r.message = message
	r.runbooks = runbooks

	return r
}
