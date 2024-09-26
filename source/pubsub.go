package source

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
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
}

type PubSub struct {
	options *PubSubOptions
	logger  sreCommon.Logger
	client  *pubsub.Client
}

const SourcePubSubName = "PubSub"

func (ps *PubSub) Name() string {
	return SourcePubSubName
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

func (ps *PubSub) Load() (*common.SourceResult, error) {

	ps.logger.Debug("PubSub discovery by topic %s...", ps.options.Topic)

	ctx := context.Background()
	topic := ps.client.Topic(ps.options.Topic)
	subID := ps.options.Subscription

	sub := ps.client.Subscription(subID)
	exists, err := sub.Exists(ctx)
	if err != nil {
		return nil, err
	}

	if !exists {
		sub, err = ps.client.CreateSubscription(ctx, subID, pubsub.SubscriptionConfig{
			Topic:             topic,
			AckDeadline:       time.Duration(ps.options.AckDeadline) * time.Second,
			RetentionDuration: time.Duration(ps.options.Retention) * time.Second,
		})
		if err != nil {
			return nil, err
		}
		ps.logger.Debug("PubSub subscription %s was created", subID)
	}

	err = sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {

		var pm discovery.PubSubMessage
		err := json.Unmarshal(msg.Data, &pm)
		if err != nil {
			msg.Nack()
			ps.logger.Error("PubSub couldn't unmarshal from %s error: %s", subID, err)
			return
		}

		m := make(map[string]interface{})

		for k, v := range pm.Payload {

			ps.logger.Debug("PubSub is processing payload %s from %s", k, subID)

			if v.Kind == discovery.PubSubMessagePayloadKindUnknown {
				ps.logger.Error("PubSub couldn't process unknown payload %s from %s error: %s", k, subID, err)
				continue
			}

			data, err := ps.decompress(v)
			if err != nil {
				ps.logger.Error("PubSub couldn't decompress payload %s from %s error: %s", k, subID, err)
				continue
			}

			switch v.Kind {
			case discovery.PubSubMessagePayloadKindFile:

				var f discovery.PubSubMessagePayloadFile
				err := json.Unmarshal(data, &f)
				if err != nil {
					ps.logger.Error("PubSub couldn't unmarshall payload %s from %s to file error: %s", k, subID, err)
					continue
				}
				name := filepath.Base(f.Path)
				m[name] = &f

			case discovery.PubSubMessagePayloadKindFiles:

				var fs []*discovery.PubSubMessagePayloadFile
				err := json.Unmarshal(data, &fs)
				if err != nil {
					ps.logger.Error("PubSub couldn't unmarshall payload %s from %s to files error: %s", k, subID, err)
					continue
				}

				for _, f := range fs {
					name := filepath.Base(f.Path)
					m[name] = f
				}
			case discovery.PubSubMessagePayloadKindUnknown:
				ps.logger.Error("PubSub couldn't process unknown payload %s from %s", k, subID)
			}
		}
		msg.Ack()

		//
	})

	if err != nil {
		ps.logger.Error("PubSub couldn't receive messages from %s error: %s", subID, err)
		return nil, err
	}
	return nil, nil
}

func NewPubSub(options *PubSubOptions, observability *common.Observability) *PubSub {

	logger := observability.Logs()

	if utils.IsEmpty(options.Credentials) || utils.IsEmpty(options.Topic) ||
		utils.IsEmpty(options.Subscription) || utils.IsEmpty(options.Project) {
		logger.Debug("PubSub is disabled. Skipped")
		return nil
	}

	data, err := utils.Content(options.Credentials)
	if err != nil {
		logger.Debug("PubSub credentials error: %s", err)
		return nil
	}

	o := option.WithCredentialsJSON(data)

	client, err := pubsub.NewClient(context.Background(), options.Project, o)
	if err != nil {
		logger.Error("PubSub new client error: %s", err)
		return nil
	}

	return &PubSub{
		options: options,
		logger:  logger,
		client:  client,
	}
}
