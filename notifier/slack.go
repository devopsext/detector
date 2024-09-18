package notifier

import (
	"encoding/json"
	"errors"
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
}

type Slack struct {
	options  SlackOptions
	logger   sreCommon.Logger
	client   *vendors.Slack
	message  *toolsRender.TextTemplate
	runbooks *toolsRender.TextTemplate
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

	if vr.Endpoints.IsEmpty() {
		return errors.New("Slack cannot process empty endpoints")
	}

	s.logger.Debug("Slack is notifying...")

	t1 := time.Now()

	d, err := s.renderTemplate(s.message, vr)
	if err != nil {
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
		return err
	}

	mr := vendors.SlackMessageResponse{}
	err = json.Unmarshal(r, &mr)
	if err != nil {
		return err
	}

	err = s.execute(&mr, vr)
	if err != nil {
		s.message.LogError(err)
	}

	s.logger.Debug("Slack notified in %s", time.Since(t1))

	return nil
}

func (s *Slack) fIndirect(obj interface{}) interface{} {

	v1 := reflect.ValueOf(obj)
	v2 := reflect.Indirect(v1)
	return v2.Interface()
}

func NewSlack(options SlackOptions, observability *common.Observability) *Slack {

	logger := observability.Logs()

	if utils.IsEmpty(options.Token) {
		logger.Debug("Slack token is not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.Message) {
		logger.Debug("Slack message is not defined. Skipped.")
		return nil
	}

	r := &Slack{
		options: options,
		logger:  logger,
	}

	funcs := make(map[string]any)
	funcs["indirect"] = r.fIndirect

	messageOpts := toolsRender.TemplateOptions{
		Content: options.Message,
		Funcs:   funcs,
	}
	message, err := toolsRender.NewTextTemplate(messageOpts, observability)
	if err != nil {
		logger.Error("Slack message error: %s", err)
		return nil
	}

	runbooksOpts := toolsRender.TemplateOptions{
		Content: options.Runbooks,
		Funcs:   funcs,
	}
	runbooks, err := toolsRender.NewTextTemplate(runbooksOpts, observability)
	if err != nil {
		logger.Error("Slack runbooks error: %s", err)
	}

	r.client = vendors.NewSlack(options.SlackOptions)
	r.message = message
	r.runbooks = runbooks

	return r
}
