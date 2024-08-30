package common

import (
	"maps"
	"slices"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type SourceEndpointResponse struct {
	Code    string `json:"code,omitempty"`
	Content string `json:"content,omitempty"`
}

type SourceEndpoint struct {
	URI       string                  `json:"uri"`
	Disabled  bool                    `json:"disabled"`
	Countries []string                `json:"countries,omitempty"`
	Response  *SourceEndpointResponse `json:"response,omitempty"`
}

type SourceEndpoints = []*SourceEndpoint

type SourceResult struct {
	Source    Source
	Endpoints SourceEndpoints
}

type Source interface {
	Name() string
	Load() (*SourceResult, error)
}

type Sources struct {
	logger sreCommon.Logger
	items  []Source
}

func (ss *Sources) Add(s Source) {

	if utils.IsEmpty(s) {
		return
	}
	ss.items = append(ss.items, s)
}

func (ss *Sources) Items() []Source {
	return ss.items
}

func (ss *Sources) FindByPattern(pattern string) map[string]Source {

	r := make(map[string]Source)

	if len(ss.items) == 0 {
		return r
	}

	if utils.IsEmpty(pattern) {
		return r
	}

	m := utils.MapGetKeyValues(pattern)
	if len(m) == 0 {
		return r
	}
	keys := slices.Collect(maps.Keys(m))

	for _, s := range ss.items {

		name := s.Name()
		if !utils.Contains(keys, name) {
			continue
		}
		r[name] = s
	}
	return r
}

func NewSources(observability *Observability) *Sources {

	return &Sources{
		logger: observability.Logs(),
	}
}
