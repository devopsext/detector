package common

import (
	"time"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"github.com/jellydator/ttlcache/v3"
)

type TriggerOptions struct {
	TTL string
}

type Triggers struct {
	options *TriggerOptions
	logger  sreCommon.Logger
	cache   *ttlcache.Cache[string, *VerifyEndpoint]
}

func (t *Triggers) Exists(key string) bool {

	return t.cache.Has(key)
}

func (t *Triggers) Update(key string, ep *VerifyEndpoint) {

	if ep == nil {
		return
	}

	// if there is no entry create it
	if !t.cache.Has(key) {
		t.cache.Set(key, ep, ttlcache.PreviousOrDefaultTTL)
		return
	}
}

func NewTriggers(options *TriggerOptions, observability *Observability) *Triggers {

	logger := observability.Logs()

	opts := []ttlcache.Option[string, *VerifyEndpoint]{}
	if options != nil && !utils.IsEmpty(options.TTL) {

		ttl, err := time.ParseDuration(options.TTL)
		if err == nil {
			opts = append(opts, ttlcache.WithTTL[string, *VerifyEndpoint](ttl))
		}
	}

	cache := ttlcache.New[string, *VerifyEndpoint](opts...)
	go cache.Start()

	return &Triggers{
		options: options,
		logger:  logger,
		cache:   cache,
	}
}
