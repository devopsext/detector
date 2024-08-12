package source

import (
	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type ConfigFile struct {
	Interval  string
	Endpoints []string
}

type ConfigOptions struct {
	Path string
}

type Config struct {
	options ConfigOptions
	logger  sreCommon.Logger
}

func (cs *Config) Load() error {

	return nil
}

func NewConfig(options ConfigOptions, observability *common.Observability) *Config {

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
