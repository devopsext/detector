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
	cache   *ttlcache.Cache[string, any]
}

func (t *Triggers) Exists(key string) bool {

	return t.cache.Has(key)
}

func (t *Triggers) Update(key string, ep any) {

	if ep == nil {
		return
	}
	t.cache.Set(key, ep, ttlcache.PreviousOrDefaultTTL)
}

func NewTriggers(options *TriggerOptions, observability *Observability) *Triggers {

	if options == nil {
		return nil
	}

	logger := observability.Logs()
	opts := []ttlcache.Option[string, any]{}

	ttl := 1 * 60 * 60 * time.Second

	if !utils.IsEmpty(options.TTL) {
		ttl, _ = time.ParseDuration(options.TTL)
	}

	opts = append(opts, ttlcache.WithTTL[string, any](ttl))

	cache := ttlcache.New[string, any](opts...)
	go cache.Start()

	return &Triggers{
		options: options,
		logger:  logger,
		cache:   cache,
	}
}
