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

		var config ConfigFile
		err = json.Unmarshal(data, &config)
		if err != nil {
			continue
		}
		if len(config.Endpoints) == 0 {
			continue
		}
		es := common.CheckSourceEndpoints(config.Endpoints)
		if len(es) == 0 {
			continue
		}
		ps.smap.Store(item, es)
	}
}

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

		_, ok := ctx.Deadline()
		if ok {
			msg.Nack()
			return
		}

		var pm discovery.PubSubMessage
		err := json.Unmarshal(msg.Data, &pm)
		if err != nil {
			msg.Nack()
			ps.logger.Error("PubSub source couldn't unmarshal from %s error: %s", subID, err)
			return
		}

		m := make(map[string][]*common.SourceEndpoint)

		for k, v := range pm.Payload {

			ps.logger.Debug("PubSub source is processing payload %s from %s", k, subID)

			if v.Kind == discovery.PubSubMessagePayloadKindUnknown {
				ps.logger.Error("PubSub source couldn't process unknown payload %s from %s error: %s", k, subID, err)
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
				err := json.Unmarshal(data, &f)
				if err != nil {
					ps.logger.Error("PubSub source couldn't unmarshall payload %s from %s to file error: %s", k, subID, err)
					continue
				}

				es := []*common.SourceEndpoint{}
				err = json.Unmarshal(f.Data, &es)
				if err != nil {
					continue
				}
				es = common.CheckSourceEndpoints(es)
				if len(es) > 0 {
					path := ps.replace(f.Path)
					m[path] = es
				}

			case discovery.PubSubMessagePayloadKindFiles:

				var fs []*discovery.PubSubMessagePayloadFile
				err := json.Unmarshal(data, &fs)
				if err != nil {
					ps.logger.Error("PubSub source couldn't unmarshall payload %s from %s to files error: %s", k, subID, err)
					continue
				}

				for _, f := range fs {
					es := []*common.SourceEndpoint{}
					err = json.Unmarshal(f.Data, &es)
					if err != nil {
						continue
					}
					es = common.CheckSourceEndpoints(es)
					if len(es) == 0 {
						return
					}
					path := ps.replace(f.Path)
					m[path] = es
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

func (ps *PubSub) Load() (*common.SourceResult, error) {

	es := common.SourceEndpoints{}

	ps.smap.Range(func(key, value any) bool {

		arr, ok := value.([]*common.SourceEndpoint)
		if !ok {
			return false
		}
		es.Add(arr...)
		return true
	})

	r := &common.SourceResult{
		Endpoints: es,
	}
	return r, nil
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
