package common

import (
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
	IPs       []string                `json:"ips,omitempty"`
	Detectors []string                `json:"detectors,omitempty"`
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

func (ss *Sources) FindByName(name string) Source {

	for _, s := range ss.items {

		if s.Name() == name {
			return s
		}
	}
	return nil
}

func NewSources(observability *Observability) *Sources {

	return &Sources{
		logger: observability.Logs(),
	}
}
