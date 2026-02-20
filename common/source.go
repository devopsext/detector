package common

import (
	"context"
	"strings"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

// SourceEndpointResponse holds expected response criteria for an endpoint.
type SourceEndpointResponse struct {
	Code    string `json:"code,omitempty"    yaml:"code,omitempty"`
	Content string `json:"content,omitempty" yaml:"content,omitempty"`
}

// SourceEndpoint represents a single endpoint entry for the Simple detector.
type SourceEndpoint struct {
	URI          string                  `json:"uri"                    yaml:"uri"`
	Disabled     bool                    `json:"disabled"               yaml:"disabled"`
	DetectorName string                  `json:"detectorName,omitempty" yaml:"detectorName,omitempty"`
	Countries    []string                `json:"countries,omitempty"    yaml:"countries,omitempty"`
	IPs          []string                `json:"ips,omitempty"          yaml:"ips,omitempty"`
	Detectors    []string                `json:"detectors,omitempty"    yaml:"detectors,omitempty"`
	Response     *SourceEndpointResponse `json:"response,omitempty"     yaml:"response,omitempty"`
}

// SourceEndpoints holds a collection of SourceEndpoint items.
type SourceEndpoints struct {
	items []*SourceEndpoint
}

// SourceApplication represents a single application entry for the Application detector.
type SourceApplication struct {
	Application  string   `json:"application"            yaml:"application"`
	Disabled     bool     `json:"disabled"               yaml:"disabled"`
	DetectorName string   `json:"detectorName,omitempty" yaml:"detectorName,omitempty"`
	Countries    []string `json:"countries,omitempty"    yaml:"countries,omitempty"`
	Detectors    []string `json:"detectors,omitempty"    yaml:"detectors,omitempty"`
}

// SourceApplications holds a collection of SourceApplication items.
type SourceApplications struct {
	items []*SourceApplication
}

// SourceProcess represents a single business process entry for the Process detector.
type SourceProcess struct {
	BusinessProcesses string   `json:"businessProcesses"      yaml:"businessProcesses"`
	Disabled          bool     `json:"disabled"               yaml:"disabled"`
	DetectorName      string   `json:"detectorName,omitempty" yaml:"detectorName,omitempty"`
	Countries         []string `json:"countries,omitempty"    yaml:"countries,omitempty"`
	Detectors         []string `json:"detectors,omitempty"    yaml:"detectors,omitempty"`
}

// SourceProcesses holds a collection of SourceProcess items.
type SourceProcesses struct {
	items []*SourceProcess
}

// SourceEntry is the flat catalog item format used in PubSub messages.
// Each entry carries a detectorType field that determines which detector will process it.
// The Name field is a display-only label from the service catalog, not used by application logic.
type SourceEntry struct {
	Disabled          bool     `json:"disabled"`
	DetectorType      string   `json:"detectorType"`
	Name              string   `json:"name"`      // display-only label from service catalog
	Detectors         []string `json:"detectors"` // list of detector names allowed to process this entry
	Countries         []string `json:"countries,omitempty"`
	URI               string   `json:"uri,omitempty"`               // endpoint type
	Application       string   `json:"application,omitempty"`       // application type
	BusinessProcesses string   `json:"businessProcesses,omitempty"` // process type
}

// SourceResult carries typed source data for each detector kind.
type SourceResult struct {
	Endpoints    SourceEndpoints    // consumed by Simple detector
	Applications SourceApplications // consumed by Application detector
	Processes    SourceProcesses    // consumed by Process detector
}

// Source is the interface implemented by all data sources.
type Source interface {
	Name() string
	Start(ctx context.Context) error
	Load() (*SourceResult, error)
}

// Sources manages a collection of Source instances.
type Sources struct {
	logger sreCommon.Logger
	items  []Source
}

// --- CheckSourceEndpoints ---

// CheckSourceEndpoints filters out nil or empty-URI endpoints.
func CheckSourceEndpoints(es []*SourceEndpoint) []*SourceEndpoint {
	var r []*SourceEndpoint
	for _, p := range es {
		if p == nil {
			continue
		}
		if utils.IsEmpty(p.URI) {
			continue
		}
		r = append(r, p)
	}
	return r
}

// --- SourceEndpoints ---

// Clone returns a deep copy of ep.
func (ses *SourceEndpoints) Clone(ep *SourceEndpoint) *SourceEndpoint {
	var r *SourceEndpointResponse
	if ep.Response != nil {
		r = &SourceEndpointResponse{
			Code:    ep.Response.Code,
			Content: ep.Response.Content,
		}
	}
	return &SourceEndpoint{
		URI:          ep.URI,
		Disabled:     ep.Disabled,
		DetectorName: ep.DetectorName,
		Countries:    ep.Countries,
		IPs:          ep.IPs,
		Detectors:    ep.Detectors,
		Response:     r,
	}
}

func (ses *SourceEndpoints) Add(e ...*SourceEndpoint) {
	ses.items = append(ses.items, e...)
}

func (ses *SourceEndpoints) Items() []*SourceEndpoint {
	return ses.items
}

func (ses *SourceEndpoints) IsEmpty() bool {
	return len(ses.items) == 0
}

// Reduce merges endpoints with the same URI, combining countries, IPs and responses.
func (ses *SourceEndpoints) Reduce() SourceEndpoints {
	uris := make(map[string][]*SourceEndpoint)
	for _, ep := range ses.items {
		if ep == nil {
			continue
		}
		uri := NormalizeURI(ep.URI)
		uris[uri] = append(uris[uri], ep)
	}

	r := SourceEndpoints{}
	for uri, items := range uris {
		countries := []string{}
		ips := []string{}
		responses := []*SourceEndpointResponse{}

		for _, item := range items {
			for _, c := range item.Countries {
				if utils.Contains(countries, c) {
					continue
				}
				countries = append(countries, c)
			}
			for _, ip := range item.IPs {
				if utils.Contains(ips, ip) {
					continue
				}
				ips = append(ips, ip)
			}
			if item.Response != nil {
				responses = append(responses, item.Response)
			}
		}

		var response *SourceEndpointResponse
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
			response = &SourceEndpointResponse{Code: code, Content: content}
		}

		r.Add(&SourceEndpoint{
			URI:       uri,
			Countries: countries,
			IPs:       ips,
			Response:  response,
		})
	}
	return r
}

// --- SourceApplications ---

// Clone returns a deep copy of sa.
func (sas *SourceApplications) Clone(sa *SourceApplication) *SourceApplication {
	return &SourceApplication{
		Application:  sa.Application,
		Disabled:     sa.Disabled,
		DetectorName: sa.DetectorName,
		Countries:    sa.Countries,
		Detectors:    sa.Detectors,
	}
}

func (sas *SourceApplications) Add(e ...*SourceApplication) {
	sas.items = append(sas.items, e...)
}

func (sas *SourceApplications) Items() []*SourceApplication {
	return sas.items
}

func (sas *SourceApplications) IsEmpty() bool {
	return len(sas.items) == 0
}

// Reduce merges applications with the same Application name.
func (sas *SourceApplications) Reduce() SourceApplications {
	groups := make(map[string][]*SourceApplication)
	for _, sa := range sas.items {
		if sa == nil {
			continue
		}
		groups[sa.Application] = append(groups[sa.Application], sa)
	}

	r := SourceApplications{}
	for app, items := range groups {
		countries := []string{}
		detectors := []string{}
		for _, item := range items {
			for _, c := range item.Countries {
				if !utils.Contains(countries, c) {
					countries = append(countries, c)
				}
			}
			for _, d := range item.Detectors {
				if !utils.Contains(detectors, d) {
					detectors = append(detectors, d)
				}
			}
		}
		r.Add(&SourceApplication{
			Application: app,
			Countries:   countries,
			Detectors:   detectors,
		})
	}
	return r
}

// --- SourceProcesses ---

// Clone returns a deep copy of sp.
func (sps *SourceProcesses) Clone(sp *SourceProcess) *SourceProcess {
	return &SourceProcess{
		BusinessProcesses: sp.BusinessProcesses,
		Disabled:          sp.Disabled,
		DetectorName:      sp.DetectorName,
		Countries:         sp.Countries,
		Detectors:         sp.Detectors,
	}
}

func (sps *SourceProcesses) Add(e ...*SourceProcess) {
	sps.items = append(sps.items, e...)
}

func (sps *SourceProcesses) Items() []*SourceProcess {
	return sps.items
}

func (sps *SourceProcesses) IsEmpty() bool {
	return len(sps.items) == 0
}

// Reduce merges processes with the same BusinessProcesses name.
func (sps *SourceProcesses) Reduce() SourceProcesses {
	groups := make(map[string][]*SourceProcess)
	for _, sp := range sps.items {
		if sp == nil {
			continue
		}
		groups[sp.BusinessProcesses] = append(groups[sp.BusinessProcesses], sp)
	}

	r := SourceProcesses{}
	for bp, items := range groups {
		countries := []string{}
		detectors := []string{}
		for _, item := range items {
			for _, c := range item.Countries {
				if !utils.Contains(countries, c) {
					countries = append(countries, c)
				}
			}
			for _, d := range item.Detectors {
				if !utils.Contains(detectors, d) {
					detectors = append(detectors, d)
				}
			}
		}
		r.Add(&SourceProcess{
			BusinessProcesses: bp,
			Countries:         countries,
			Detectors:         detectors,
		})
	}
	return r
}

// --- RouteEntries ---

// RouteEntries distributes a flat SourceEntry slice into a typed SourceResult
// based on each entry's DetectorType field.
func RouteEntries(entries []*SourceEntry) *SourceResult {
	r := &SourceResult{}
	for _, e := range entries {
		if e == nil || e.Disabled {
			continue
		}

		detectors := e.Detectors
		if len(detectors) == 0 && !utils.IsEmpty(e.Name) {
			detectors = []string{e.Name}
		}

		switch e.DetectorType {
		case "endpoint":
			r.Endpoints.Add(&SourceEndpoint{
				URI:          e.URI,
				DetectorName: e.Name,
				Countries:    e.Countries,
				Detectors:    detectors,
			})
		case "application":
			r.Applications.Add(&SourceApplication{
				Application:  e.Application,
				DetectorName: e.Name,
				Countries:    e.Countries,
				Detectors:    detectors,
			})
		case "process":
			r.Processes.Add(&SourceProcess{
				BusinessProcesses: e.BusinessProcesses,
				DetectorName:      e.Name,
				Countries:         e.Countries,
				Detectors:         detectors,
			})
		}
	}
	return r
}

// --- Sources ---

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
