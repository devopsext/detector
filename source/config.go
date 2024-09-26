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

type ConfigFile struct {
	Endpoints []*common.SourceEndpoint
}

type ConfigOptions struct {
	Path string
}

type Config struct {
	options *ConfigOptions
	logger  sreCommon.Logger
}

const SourceConfigName = "Config"

// Config

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
		err := json.Unmarshal([]byte(raw), config)
		if err != nil {
			return nil, err
		}
	case (ext == "yaml") || (ext == "yml"):
		err := yaml.Unmarshal([]byte(raw), config)
		if err != nil {
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

func (cs *Config) Load() (*common.SourceResult, error) {

	cs.logger.Debug("Config is loading...")

	t1 := time.Now()

	config, err := cs.loadFile(cs.options.Path)
	if err != nil {
		return nil, fmt.Errorf("Config cannot read from file %s, error: %s", cs.options.Path, err)
	}

	cs.logger.Debug("Config was loaded in %s", time.Since(t1))

	e := common.SourceEndpoints{}
	e.Add(config.Endpoints...)

	r := &common.SourceResult{
		Endpoints: e,
	}

	return r, nil
}

func NewConfig(options *ConfigOptions, observability *common.Observability) *Config {

	logger := observability.Logs()
	if utils.IsEmpty(options.Path) {
		logger.Debug("Config path is not defined. Skipped.")
		return nil
	}

	return &Config{
		options: options,
		logger:  logger,
	}
}
