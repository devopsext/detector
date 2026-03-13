package notifier

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type ChatopsOptions struct {
	URL      string
	Bot      string
	Channel  string
	UserID   string
	Timeout  int
	Insecure bool
}

type ChatopsMessageStatus string

const (
	ChatopsStatusPending         ChatopsMessageStatus = "pending"
	ChatopsStatusDelivered       ChatopsMessageStatus = "delivered"
	ChatopsStatusFailed          ChatopsMessageStatus = "failed"
	ChatopsStatusWaitingApproval ChatopsMessageStatus = "waiting_approval"
	ChatopsStatusRejected        ChatopsMessageStatus = "rejected"
	ChatopsStatusNotFound        ChatopsMessageStatus = "not_found"
)

type chatopsCreateMessageRequest struct {
	Bot     string `json:"bot"`
	Channel string `json:"channel"`
	Command string `json:"command"`
	UserID  string `json:"user_id"`
}

type chatopsCreateMessageResponse struct {
	ID string `json:"id"`
}

type chatopsGetStatusResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type chatopsErrorResponse struct {
	Error string `json:"error"`
}

type Chatops struct {
	options ChatopsOptions
	logger  sreCommon.Logger
	client  *http.Client
	metrics *common.VerifierMetrics
}

const NotifierChatopsName = "Chatops"

func (c *Chatops) Name() string {
	return NotifierChatopsName
}

func (c *Chatops) Notify(vr *common.VerifyResult) error {
	return errors.New("Chatops notifier does not support simple pipeline, use NotifyDefault")
}

func (c *Chatops) NotifyDefault(vr *common.VerifyDefaultResult) error {

	if vr.IsEmpty() {
		return errors.New("Chatops notifier cannot process empty verify result")
	}

	c.logger.Debug("Chatops notifier is processing %d item(s)...", len(vr.Items))

	var errs []error
	for i, item := range vr.Items {
		singleResult := &common.VerifyDefaultResult{
			Items: []*common.VerifyDefaultItem{item},
		}
		itemLabel := fmt.Sprintf("item_%d", i)
		if _, err := c.sendMessage(singleResult, itemLabel); err != nil {
			c.logger.Error("Chatops notifier failed on %s: %s", itemLabel, err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("Chatops notifier encountered %d error(s): %w", len(errs), errors.Join(errs...))
	}

	return nil
}

func (c *Chatops) NotifyDefaultWithTracking(vr *common.VerifyDefaultResult) ([]*common.NotifyDefaultTrackingItem, error) {

	if vr.IsEmpty() {
		return nil, errors.New("Chatops notifier cannot process empty verify result")
	}

	c.logger.Debug("Chatops notifier (tracked) is processing %d item(s)...", len(vr.Items))

	var tracking []*common.NotifyDefaultTrackingItem
	var errs []error

	for i, item := range vr.Items {
		singleResult := &common.VerifyDefaultResult{
			Items: []*common.VerifyDefaultItem{item},
		}
		itemLabel := fmt.Sprintf("item_%d", i)
		msgID, err := c.sendMessage(singleResult, itemLabel)
		if err != nil {
			c.logger.Error("Chatops notifier (tracked) failed on %s: %s", itemLabel, err)
			errs = append(errs, err)
			continue
		}
		tracking = append(tracking, &common.NotifyDefaultTrackingItem{
			ItemIndex: i,
			MessageID: msgID,
		})
	}

	if len(errs) > 0 && len(tracking) == 0 {
		return nil, fmt.Errorf("Chatops notifier (tracked) all %d item(s) failed: %w", len(errs), errors.Join(errs...))
	}

	return tracking, nil
}

func (c *Chatops) CheckMessageStatus(id string) (string, error) {

	status, err := c.GetMessageStatus(id)
	if err != nil {
		return "", err
	}
	return string(status), nil
}

func (c *Chatops) sendMessage(vr *common.VerifyDefaultResult, itemLabel string) (string, error) {

	if c.metrics != nil {
		c.metrics.RecordTestStartByType("notifier", "chatops", "chatops_api", itemLabel)
	}

	t1 := time.Now()

	command, err := c.buildCommand(vr)
	if err != nil {
		if c.metrics != nil {
			c.metrics.RecordTestErrorByType("notifier", "chatops", "chatops_api", itemLabel, "command_build_error", 0)
		}
		return "", fmt.Errorf("command build error: %w", err)
	}

	req := chatopsCreateMessageRequest{
		Bot:     c.options.Bot,
		Channel: c.options.Channel,
		Command: command,
		UserID:  c.options.UserID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		if c.metrics != nil {
			c.metrics.RecordTestErrorByType("notifier", "chatops", "chatops_api", itemLabel, "request_marshal_error", 0)
		}
		return "", fmt.Errorf("request marshal error: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/message", c.options.URL)
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		if c.metrics != nil {
			c.metrics.RecordTestErrorByType("notifier", "chatops", "chatops_api", itemLabel, "request_create_error", 0)
		}
		return "", fmt.Errorf("request create error: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		if c.metrics != nil {
			c.metrics.RecordTestErrorByType("notifier", "chatops", "chatops_api", itemLabel, "http_error", 0)
		}
		return "", fmt.Errorf("HTTP error: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		if c.metrics != nil {
			c.metrics.RecordTestErrorByType("notifier", "chatops", "chatops_api", itemLabel, "response_read_error", 0)
		}
		return "", fmt.Errorf("response read error: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		var errResp chatopsErrorResponse
		json.Unmarshal(respBody, &errResp)
		if c.metrics != nil {
			c.metrics.RecordTestErrorByType("notifier", "chatops", "chatops_api", itemLabel, "api_error", 0)
		}
		return "", fmt.Errorf("API error (status %d): %s", resp.StatusCode, errResp.Error)
	}

	var msgResp chatopsCreateMessageResponse
	if err := json.Unmarshal(respBody, &msgResp); err != nil {
		if c.metrics != nil {
			c.metrics.RecordTestErrorByType("notifier", "chatops", "chatops_api", itemLabel, "response_unmarshal_error", 0)
		}
		return "", fmt.Errorf("response unmarshal error: %w", err)
	}

	if c.metrics != nil {
		c.metrics.RecordTestSuccessByType("notifier", "chatops", "chatops_api", itemLabel, float64(time.Since(t1).Seconds()))
	}

	c.logger.Info("Chatops notifier sent command [%s], message ID: %s", itemLabel, msgResp.ID)
	c.logger.Debug("Chatops notifier [%s] spent %s", itemLabel, time.Since(t1))

	return msgResp.ID, nil
}

func (c *Chatops) buildCommand(vr *common.VerifyDefaultResult) (string, error) {

	if len(vr.Items) > 0 && vr.Items[0].Severity == "alert" {
		item := vr.Items[0]
		return c.buildCaseDailyCommand(item), nil
	}

	data, err := json.Marshal(vr)
	if err != nil {
		return "", fmt.Errorf("marshal error: %w", err)
	}
	return fmt.Sprintf("anomaly %s", string(data)), nil
}

func (c *Chatops) buildCaseDailyCommand(item *common.VerifyDefaultItem) string {

	app := item.Labels["application"]
	group := item.Labels["group"]
	process := item.Labels["process"]

	summary := "availability degradation :arrow_down_red:"
	if !isEmptyLabel(app) {
		summary = fmt.Sprintf("%s availability degradation :arrow_down_red:", app)
	}

	var parts []string
	parts = append(parts, fmt.Sprintf("case daily [%s]", summary))

	if !isEmptyLabel(app) {
		parts = append(parts, fmt.Sprintf("[%s]", app))
	}

	if !isEmptyLabel(group) {
		parts = append(parts, group)
	}

	if !isEmptyLabel(process) {
		parts = append(parts, fmt.Sprintf("[bp:%s]", process))
	}

	cmd := strings.Join(parts, " ")
	c.logger.Debug("Chatops built case daily command: %s", cmd)
	return cmd
}

func isEmptyLabel(v string) bool {
	if v == "" {
		return true
	}
	norm := strings.ToLower(strings.TrimSpace(v))
	return norm == "n/a" || norm == "na" || norm == "none" || norm == "null" || norm == "undefined"
}

func buildSummaryFromLabels(labels map[string]string, value float64) string {

	keys := make([]string, 0, len(labels))
	for k := range labels {
		if !isEmptyLabel(labels[k]) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys)+1)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, labels[k]))
	}
	parts = append(parts, fmt.Sprintf("value=%.2f%%", value))
	return strings.Join(parts, ", ")
}

func (c *Chatops) GetMessageStatus(id string) (ChatopsMessageStatus, error) {

	endpoint := fmt.Sprintf("%s/api/v1/message/status", c.options.URL)

	u, err := url.Parse(endpoint)
	if err != nil {
		return ChatopsStatusNotFound, fmt.Errorf("Chatops status URL parse error: %w", err)
	}
	q := u.Query()
	q.Set("bot", c.options.Bot)
	q.Set("id", id)
	u.RawQuery = q.Encode()

	resp, err := c.client.Get(u.String())
	if err != nil {
		return ChatopsStatusNotFound, fmt.Errorf("Chatops status HTTP error: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ChatopsStatusNotFound, fmt.Errorf("Chatops status response read error: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp chatopsErrorResponse
		json.Unmarshal(body, &errResp)
		return ChatopsStatusNotFound, fmt.Errorf("Chatops status API error (status %d): %s", resp.StatusCode, errResp.Error)
	}

	var statusResp chatopsGetStatusResponse
	if err := json.Unmarshal(body, &statusResp); err != nil {
		return ChatopsStatusNotFound, fmt.Errorf("Chatops status response unmarshal error: %w", err)
	}

	return ChatopsMessageStatus(statusResp.Status), nil
}

func NewChatops(options ChatopsOptions, observability *common.Observability, metrics *common.VerifierMetrics) *Chatops {

	logger := observability.Logs()

	if utils.IsEmpty(options.URL) {
		logger.Debug("Chatops notifier URL is not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.Bot) {
		logger.Debug("Chatops notifier bot is not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.Channel) {
		logger.Debug("Chatops notifier channel is not defined. Skipped.")
		return nil
	}

	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 30
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: options.Insecure},
	}

	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
	}

	return &Chatops{
		options: options,
		logger:  logger,
		client:  client,
		metrics: metrics,
	}
}
