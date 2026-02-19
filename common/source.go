package common

import (
	"context"
	"strings"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type SourceItemResponse struct {
	Code    string `json:"code,omitempty"`
	Content string `json:"content,omitempty"`
}

type SourceItem struct {
	Key       string              `json:"key,omitempty"` // universal primary key (BP: "deposit", Frontend: "web-trader:panel")
	URI       string              `json:"uri,omitempty"` // domain (backward compat)
	Disabled  bool                `json:"disabled"`
	Countries []string            `json:"countries,omitempty"`
	IPs       []string            `json:"ips,omitempty"`
	Detectors []string            `json:"detectors,omitempty"`
	Response  *SourceItemResponse `json:"response,omitempty"`
}

// EntryKey returns the primary grouping key.
// Returns Key if set explicitly (BP, Frontend), otherwise NormalizeURI(URI) for domains.
func (se *SourceItem) EntryKey() string {
	if se.Key != "" {
		return se.Key
	}
	return NormalizeURI(se.URI)
}

func (se *SourceItem) EntryIdent() string       { return se.EntryKey() }
func (se *SourceItem) EntryCountries() []string { return se.Countries }
func (se *SourceItem) EntryDisabled() bool      { return se.Disabled }
func (se *SourceItem) EntryDetectors() []string { return se.Detectors }

// Compile-time check that *SourceItem implements SourceEntry.
var _ SourceEntry = (*SourceItem)(nil)

type SourceItems struct {
	items []SourceEntry
}

type SourceResult struct {
	Items SourceItems
}

type Source interface {
	Name() string
	Start(ctx context.Context) error
	Load() (*SourceResult, error)
}

type Sources struct {
	logger sreCommon.Logger
	items  []Source
}

// CheckSourceItems filters out nil or empty-key items.
func CheckSourceItems(es []*SourceItem) []*SourceItem {
	var r []*SourceItem
	for _, p := range es {
		if p == nil {
			continue
		}
		if utils.IsEmpty(p.EntryKey()) {
			continue
		}
		r = append(r, p)
	}
	return r
}

// SourceItems

func (ses *SourceItems) Clone(se *SourceItem) *SourceItem {

	var r *SourceItemResponse
	if se.Response != nil {
		r = &SourceItemResponse{
			Code:    se.Response.Code,
			Content: se.Response.Content,
		}
	}

	return &SourceItem{
		Key:       se.Key,
		URI:       se.URI,
		Disabled:  se.Disabled,
		Countries: se.Countries,
		IPs:       se.IPs,
		Detectors: se.Detectors,
		Response:  r,
	}
}

func (ses *SourceItems) Add(e ...SourceEntry) {
	ses.items = append(ses.items, e...)
}

func (ses *SourceItems) Items() []SourceEntry {
	return ses.items
}

func (ses *SourceItems) IsEmpty() bool {
	return len(ses.items) == 0
}

func (ses *SourceItems) Reduce() SourceItems {

	// group by EntryKey
	groups := make(map[string][]SourceEntry)
	for _, entry := range ses.items {
		if entry == nil {
			continue
		}
		k := entry.EntryKey()
		groups[k] = append(groups[k], entry)
	}

	r := SourceItems{}

	for key, items := range groups {

		countries := []string{}
		ips := []string{}
		responses := []*SourceItemResponse{}

		for _, item := range items {

			for _, c := range item.EntryCountries() {
				if utils.Contains(countries, c) {
					continue
				}
				countries = append(countries, c)
			}

			// domain-specific fields via type assertion
			if ep, ok := item.(*SourceItem); ok {
				for _, ip := range ep.IPs {
					if utils.Contains(ips, ip) {
						continue
					}
					ips = append(ips, ip)
				}
				if ep.Response != nil {
					responses = append(responses, ep.Response)
				}
			}
		}

		var response *SourceItemResponse
		if len(responses) > 0 {

			codes := []string{}
			contents := []string{}

			for _, res := range responses {
				if !utils.IsEmpty(res.Code) && !utils.Contains(codes, res.Code) {
					codes = append(codes, res.Code)
				}
				if !utils.IsEmpty(res.Content) && !utils.Contains(contents, res.Content) {
					contents = append(contents, res.Content)
				}
			}

			code := ""
			if len(codes) != 0 {
				code = strings.Join(codes, "|")
			}

			content := ""
			if len(contents) != 0 {
				content = strings.Join(contents, "|")
			}

			response = &SourceItemResponse{
				Code:    code,
				Content: content,
			}
		}

		ep := &SourceItem{
			Key:       key,
			Countries: countries,
			IPs:       ips,
			Response:  response,
		}
		r.Add(ep)
	}
	return r
}

// Sources

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
