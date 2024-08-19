package source

import (
	"errors"
	"fmt"
	"os"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"gopkg.in/yaml.v2"
)

type ConfigFile struct {
	Endpoints common.Endpoints
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

func (cs *Config) loadYaml(file string) (*ConfigFile, error) {

	if utils.IsEmpty(file) {
		return nil, nil
	}

	raw := ""

	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		raw = file
	} else {
		r, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		raw = string(r)
	}

	if utils.IsEmpty(raw) {
		return nil, nil
	}

	config := &ConfigFile{}

	err := yaml.Unmarshal([]byte(raw), config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func (cs *Config) Load() (*common.SourceResult, error) {

	config, err := cs.loadYaml(cs.options.Path)
	if err != nil {
		return nil, fmt.Errorf("Config cannot read from file %s, error: %s", cs.options.Path, err)
	}

	r := &common.SourceResult{
		Source:    cs,
		Endpoints: config.Endpoints,
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
