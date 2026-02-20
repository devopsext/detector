package source

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/devopsext/detector/common"
	discovery "github.com/devopsext/discovery/discovery"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"google.golang.org/api/option"
)

// PubSubOptions holds configuration for the PubSub source.
type PubSubOptions struct {
	Credentials  string
	Project      string
	Topic        string
	Subscription string
	AckDeadline  int
	Retention    int
	ConfigFiles  string
	Replacements string
}

// PubSub is a Google Cloud PubSub-based Source implementation.
// smap stores: path → []*common.SourceEntry (new catalog format).
type PubSub struct {
	options      *PubSubOptions
	logger       sreCommon.Logger
	client       *pubsub.Client
	smap         *sync.Map
	replacements map[string]string
}

const SourcePubSubName = "PubSub"

func (ps *PubSub) Name() string {
	return SourcePubSubName
}

func (ps *PubSub) replace(s string) string {
	r := s
	for k, v := range ps.replacements {
		r = strings.Replace(r, k, v, 1)
	}
	return r
}

func (ps *PubSub) decompress(pl *discovery.PubSubMessagePayload) ([]byte, error) {
	var data []byte
	switch pl.Compression {
	case discovery.PubSubMessagePayloadCompressionGZip:
		buf := bytes.NewReader(pl.Data)
		zr, err := gzip.NewReader(buf)
		if err != nil {
			return nil, err
		}
		d, err := io.ReadAll(zr)
		if err != nil {
			return nil, err
		}
		data = d
	case discovery.PubSubMessagePayloadCompressionNone:
		data = pl.Data
	}
	return data, nil
}

// loadFiles loads catalog entries from files matching the given glob pattern.
func (ps *PubSub) loadFiles(files string) {

	ps.logger.Debug("PubSub source is loading files from %s...", files)

	list, err := filepath.Glob(files)
	if err != nil {
		ps.logger.Debug("PubSub source couldn't find files from %s, error: %s", files, err)
		return
	}

	for _, item := range list {

		if !utils.FileExists(item) {
			continue
		}

		data, err := utils.Content(item)
		if err != nil {
			ps.logger.Debug("PubSub source couldn't load file %s, error: %s", item, err)
			continue
		}

		var entries []*common.SourceEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			ps.logger.Debug("PubSub source couldn't parse file %s as SourceEntry array, error: %s", item, err)
			continue
		}

		if len(entries) == 0 {
			continue
		}

		ps.smap.Store(item, entries)
	}
}

// Start initialises the PubSub subscription and starts receiving messages.
func (ps *PubSub) Start(ctx context.Context) error {

	if !utils.IsEmpty(ps.options.ConfigFiles) {
		ps.loadFiles(ps.options.ConfigFiles)
	}

	ps.logger.Debug("PubSub source is processing topic %s...", ps.options.Topic)

	topic := ps.client.Topic(ps.options.Topic)
	subID := ps.options.Subscription

	sub := ps.client.Subscription(subID)
	exists, err := sub.Exists(ctx)
	if err != nil {
		return err
	}

	if !exists {
		sub, err = ps.client.CreateSubscription(ctx, subID, pubsub.SubscriptionConfig{
			Topic:             topic,
			AckDeadline:       time.Duration(ps.options.AckDeadline) * time.Second,
			RetentionDuration: time.Duration(ps.options.Retention) * time.Second,
		})
		if err != nil {
			return err
		}
		ps.logger.Debug("PubSub source subscription %s was created", subID)
	}

	err = sub.Receive(ctx, func(rctx context.Context, msg *pubsub.Message) {

		var pm discovery.PubSubMessage
		if err := json.Unmarshal(msg.Data, &pm); err != nil {
			msg.Nack()
			ps.logger.Error("PubSub source couldn't unmarshal from %s error: %s", subID, err)
			return
		}

		m := make(map[string][]*common.SourceEntry)

		for k, v := range pm.Payload {

			ps.logger.Debug("PubSub source is processing payload %s from %s", k, subID)

			if v.Kind == discovery.PubSubMessagePayloadKindUnknown {
				ps.logger.Error("PubSub source couldn't process unknown payload %s from %s", k, subID)
				continue
			}

			data, err := ps.decompress(v)
			if err != nil {
				ps.logger.Error("PubSub source couldn't decompress payload %s from %s error: %s", k, subID, err)
				continue
			}

			switch v.Kind {
			case discovery.PubSubMessagePayloadKindFile:

				var f discovery.PubSubMessagePayloadFile
				if err := json.Unmarshal(data, &f); err != nil {
					ps.logger.Error("PubSub source couldn't unmarshall payload %s from %s to file error: %s", k, subID, err)
					continue
				}

				path := ps.replace(f.Path)

				var entries []*common.SourceEntry
				if err := json.Unmarshal(f.Data, &entries); err != nil {
					continue
				}
				if len(entries) > 0 {
					m[path] = entries
				}

			case discovery.PubSubMessagePayloadKindFiles:

				var fs []*discovery.PubSubMessagePayloadFile
				if err := json.Unmarshal(data, &fs); err != nil {
					ps.logger.Error("PubSub source couldn't unmarshall payload %s from %s to files error: %s", k, subID, err)
					continue
				}

				for _, f := range fs {
					path := ps.replace(f.Path)
					var entries []*common.SourceEntry
					if err := json.Unmarshal(f.Data, &entries); err != nil {
						continue
					}
					if len(entries) == 0 {
						continue
					}
					m[path] = entries
				}

			case discovery.PubSubMessagePayloadKindUnknown:
				ps.logger.Error("PubSub source couldn't process unknown payload %s from %s", k, subID)
			}
		}

		if len(m) > 0 {
			ps.smap.Clear()
			for k, v := range m {
				ps.smap.Store(k, v)
			}
		}

		msg.Ack()
	})

	if err != nil {
		ps.logger.Error("PubSub source couldn't receive messages from %s error: %s", subID, err)
		return err
	}
	return nil
}

// Load collects all stored SourceEntry items and routes them into a SourceResult.
func (ps *PubSub) Load() (*common.SourceResult, error) {

	var all []*common.SourceEntry

	ps.smap.Range(func(key, value any) bool {
		entries, ok := value.([]*common.SourceEntry)
		if !ok {
			return true
		}
		all = append(all, entries...)
		return true
	})

	return common.RouteEntries(all), nil
}

func NewPubSub(options *PubSubOptions, observability *common.Observability, ctx context.Context) *PubSub {

	logger := observability.Logs()

	if utils.IsEmpty(options.Credentials) || utils.IsEmpty(options.Topic) ||
		utils.IsEmpty(options.Subscription) || utils.IsEmpty(options.Project) {
		logger.Debug("PubSub source is disabled. Skipped")
		return nil
	}

	data, err := utils.Content(options.Credentials)
	if err != nil {
		logger.Debug("PubSub source credentials error: %s", err)
		return nil
	}

	o := option.WithCredentialsJSON(data)

	client, err := pubsub.NewClient(ctx, options.Project, o)
	if err != nil {
		logger.Error("PubSub source new client error: %s", err)
		return nil
	}

	replacements := utils.MapGetKeyValues(options.Replacements)

	return &PubSub{
		options:      options,
		logger:       logger,
		client:       client,
		smap:         &sync.Map{},
		replacements: replacements,
	}
}
