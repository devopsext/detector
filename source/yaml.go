package source

import (
	"fmt"
	"os"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"gopkg.in/yaml.v2"
)

// yamlConfig represents the top-level structure of the V3 YAML configuration file.
type yamlConfig struct {
	Observers []*common.ObserverConfig        `yaml:"observers"`
	Verifiers []*common.VerifierConfig        `yaml:"verifiers"`
	Notifiers []*common.NotifierDefaultConfig `yaml:"notifiers"`
	Detectors []*common.DetectorDefaultConfig `yaml:"detectors"`
}

type YamlOptions struct {
	Path string
}

// Yaml implements common.SourceDefaultInterface.
// It reads the V3 YAML configuration file and returns structured detector and observer configs.
type Yaml struct {
	options *YamlOptions
	logger  sreCommon.Logger
}

const SourceYamlName = "Yaml"

func (y *Yaml) Name() string {
	return SourceYamlName
}

func (y *Yaml) Load() (*common.SourceDefaultResult, error) {

	if utils.IsEmpty(y.options.Path) {
		return nil, fmt.Errorf("Yaml source path is not defined")
	}

	data, err := os.ReadFile(y.options.Path)
	if err != nil {
		return nil, fmt.Errorf("Yaml source cannot read file %s: %s", y.options.Path, err)
	}

	var cfg yamlConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("Yaml source cannot parse file %s: %s", y.options.Path, err)
	}

	result := &common.SourceDefaultResult{
		Observers: cfg.Observers,
		Verifiers: cfg.Verifiers,
		Notifiers: cfg.Notifiers,
		Detectors: cfg.Detectors,
	}

	y.logger.Debug("Yaml source loaded %d observers, %d verifiers, %d notifiers and %d detectors from %s",
		len(result.Observers), len(result.Verifiers), len(result.Notifiers), len(result.Detectors), y.options.Path)

	return result, nil
}

func NewYaml(options *YamlOptions, observability *common.Observability) *Yaml {

	logger := observability.Logs()

	if utils.IsEmpty(options.Path) {
		logger.Debug("Yaml source path is not defined. Skipped.")
		return nil
	}

	return &Yaml{
		options: options,
		logger:  logger,
	}
}
