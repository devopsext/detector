package common

import (
	"time"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"github.com/jellydator/ttlcache/v3"
)

type MemoryState string

const (
	MemoryStateSent     MemoryState = "sent"
	MemoryStateApproved MemoryState = "approved"
)

type MemoryEntry struct {
	MessageID    string
	NotifierName string
	State        MemoryState
	SentAt       time.Time
}

type MemoryOptions struct {
	TTL string
}

type Memory struct {
	options    *MemoryOptions
	logger     sreCommon.Logger
	cache      *ttlcache.Cache[string, *MemoryEntry]
	defaultTTL time.Duration
}

func (m *Memory) Get(key string) *MemoryEntry {

	item := m.cache.Get(key)
	if item == nil {
		return nil
	}
	return item.Value()
}

func (m *Memory) Record(key, messageID, notifierName string) {

	entry := &MemoryEntry{
		MessageID:    messageID,
		NotifierName: notifierName,
		State:        MemoryStateSent,
		SentAt:       time.Now(),
	}
	m.cache.Set(key, entry, m.defaultTTL)
}

func (m *Memory) Approve(key string) {

	item := m.cache.Get(key)
	if item == nil {
		return
	}
	entry := item.Value()
	entry.State = MemoryStateApproved
	m.cache.Set(key, entry, ttlcache.NoTTL)
}

func (m *Memory) Delete(key string) {

	m.cache.Delete(key)
}

func NewMemory(options *MemoryOptions, observability *Observability) *Memory {

	if options == nil {
		return nil
	}

	logger := observability.Logs()

	defaultTTL := 1 * 60 * 60 * time.Second
	if !utils.IsEmpty(options.TTL) {
		parsed, err := time.ParseDuration(options.TTL)
		if err == nil {
			defaultTTL = parsed
		}
	}

	cache := ttlcache.New[string, *MemoryEntry](
		ttlcache.WithTTL[string, *MemoryEntry](defaultTTL),
	)
	go cache.Start()

	return &Memory{
		options:    options,
		logger:     logger,
		cache:      cache,
		defaultTTL: defaultTTL,
	}
}
