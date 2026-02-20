package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"gopkg.in/yaml.v2"
)

// ConfigFileEndpoint is an endpoint entry in the config file.
type ConfigFileEndpoint struct {
	URI          string                         `yaml:"uri"          json:"uri"`
	Disabled     bool                           `yaml:"disabled"     json:"disabled"`
	DetectorType string                         `yaml:"detectorType" json:"detectorType"`
	DetectorName string                         `yaml:"detectorName" json:"detectorName"`
	Countries    []string                       `yaml:"countries"    json:"countries"`
	IPs          []string                       `yaml:"ips"          json:"ips"`
	Detectors    []string                       `yaml:"detectors"    json:"detectors"`
	Response     *common.SourceEndpointResponse `yaml:"response"     json:"response"`
}

// ConfigFileApplication is an application entry in the config file.
type ConfigFileApplication struct {
	Application  string   `yaml:"application"  json:"application"`
	Disabled     bool     `yaml:"disabled"     json:"disabled"`
	DetectorType string   `yaml:"detectorType" json:"detectorType"`
	DetectorName string   `yaml:"detectorName" json:"detectorName"`
	Countries    []string `yaml:"countries"    json:"countries"`
	Detectors    []string `yaml:"detectors"    json:"detectors"`
}

// ConfigFileProcess is a business process entry in the config file.
type ConfigFileProcess struct {
	BusinessProcesses string   `yaml:"businessProcesses" json:"businessProcesses"`
	Disabled          bool     `yaml:"disabled"          json:"disabled"`
	DetectorType      string   `yaml:"detectorType"      json:"detectorType"`
	DetectorName      string   `yaml:"detectorName"      json:"detectorName"`
	Countries         []string `yaml:"countries"         json:"countries"`
	Detectors         []string `yaml:"detectors"         json:"detectors"`
}

// ConfigFile is the top-level structure of a detector config file.
// It has three sections: endpoints, applications and processes.
type ConfigFile struct {
	Endpoints    []*ConfigFileEndpoint    `yaml:"endpoints"    json:"endpoints"`
	Applications []*ConfigFileApplication `yaml:"applications" json:"applications"`
	Processes    []*ConfigFileProcess     `yaml:"processes"    json:"processes"`
}

// ConfigOptions holds configuration for the Config source.
type ConfigOptions struct {
	Path string
}

// Config is a file-based Source implementation.
type Config struct {
	options *ConfigOptions
	logger  sreCommon.Logger
}

const SourceConfigName = "Config"

func (cs *Config) Name() string {
	return SourceConfigName
}

func (cs *Config) loadFile(path string) (*ConfigFile, error) {

	if utils.IsEmpty(path) {
		return nil, nil
	}

	raw := ""

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		raw = path
	} else {
		r, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		raw = string(r)
	}

	if utils.IsEmpty(raw) {
		return nil, nil
	}

	ext := strings.Replace(filepath.Ext(path), ".", "", 1)
	if ext == "" {
		return nil, nil
	}
	ext = strings.ToLower(ext)

	config := &ConfigFile{}

	switch {
	case ext == "json":
		if err := json.Unmarshal([]byte(raw), config); err != nil {
			return nil, err
		}
	case ext == "yaml" || ext == "yml":
		if err := yaml.Unmarshal([]byte(raw), config); err != nil {
			return nil, err
		}
	default:
		return nil, nil
	}
	return config, nil
}

func (cs *Config) Start(ctx context.Context) error {
	return nil
}

// Load reads the config file and routes its sections into a SourceResult.
func (cs *Config) Load() (*common.SourceResult, error) {

	cs.logger.Debug("Config source is processing...")

	t1 := time.Now()

	config, err := cs.loadFile(cs.options.Path)
	if err != nil {
		return nil, fmt.Errorf("Config source cannot read from file %s, error: %s", cs.options.Path, err)
	}

	cs.logger.Debug("Config source spent %s", time.Since(t1))

	r := &common.SourceResult{}

	for _, ep := range config.Endpoints {
		if ep == nil || ep.Disabled {
			continue
		}

		detectors := ep.Detectors
		if len(detectors) == 0 && !utils.IsEmpty(ep.DetectorName) {
			detectors = []string{ep.DetectorName}
		}

		r.Endpoints.Add(&common.SourceEndpoint{
			URI:          ep.URI,
			DetectorName: ep.DetectorName,
			Countries:    ep.Countries,
			IPs:          ep.IPs,
			Detectors:    detectors,
			Response:     ep.Response,
		})
	}

	for _, app := range config.Applications {
		if app == nil || app.Disabled {
			continue
		}

		detectors := app.Detectors
		if len(detectors) == 0 && !utils.IsEmpty(app.DetectorName) {
			detectors = []string{app.DetectorName}
		}

		r.Applications.Add(&common.SourceApplication{
			Application:  app.Application,
			DetectorName: app.DetectorName,
			Countries:    app.Countries,
			Detectors:    detectors,
		})
	}

	for _, proc := range config.Processes {
		if proc == nil || proc.Disabled {
			continue
		}

		detectors := proc.Detectors
		if len(detectors) == 0 && !utils.IsEmpty(proc.DetectorName) {
			detectors = []string{proc.DetectorName}
		}

		r.Processes.Add(&common.SourceProcess{
			BusinessProcesses: proc.BusinessProcesses,
			DetectorName:      proc.DetectorName,
			Countries:         proc.Countries,
			Detectors:         detectors,
		})
	}

	return r, nil
}

func NewConfig(options *ConfigOptions, observability *common.Observability) *Config {

	logger := observability.Logs()
	if utils.IsEmpty(options.Path) {
		logger.Debug("Config source path is not defined. Skipped.")
		return nil
	}

	return &Config{
		options: options,
		logger:  logger,
	}
}
