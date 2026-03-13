package common

// ObserverConfig holds the configuration for a single observer entry in the V3 YAML config.
type ObserverConfig struct {
	Name         string  `yaml:"name"`
	QueryDatadog string  `yaml:"query_datadog"`
	QueryProm    string  `yaml:"query_prom"`
	Timeout      string  `yaml:"timeout"`
	Trashold     float64 `yaml:"trashold"`
}

// DetectorDefaultConfig holds the configuration for a single detector entry in the V3 YAML config.
type DetectorDefaultConfig struct {
	Name         string   `yaml:"name"`
	DetectorType string   `yaml:"detector_type"`
	Schedule     string   `yaml:"schedule"`
	Countries    []string `yaml:"countries"`
	Sources      []string `yaml:"sources"`
	Observers    []string `yaml:"observers"`
	Verifiers    []string `yaml:"verifiers"`
	Notifiers    []string `yaml:"notifiers"`
}

// VerifierConfig holds the configuration for a single verifier entry in the V3 YAML config.
type VerifierConfig struct {
	Name            string `yaml:"name"`
	URL             string `yaml:"url"`
	BusinessProcess string `yaml:"business_process"`
	Timeout         int    `yaml:"timeout"`
	TestTimeout     int    `yaml:"test_timeout"`
	TestRetries     int    `yaml:"test_retries"`
}

// NotifierDefaultConfig holds the configuration for a single notifier entry in the V3 YAML config.
type NotifierDefaultConfig struct {
	Name             string  `yaml:"name"`
	URL              string  `yaml:"url"`
	Bot              string  `yaml:"bot"`
	Channel          string  `yaml:"channel"`
	UserID           string  `yaml:"user_id"`
	Timeout          int     `yaml:"timeout"`
	Insecure         bool    `yaml:"insecure"`
	ThresholdWarning float64 `yaml:"threshold_warning"`
	ThresholdAlert   float64 `yaml:"threshold_alert"`
}

// SourceDefaultResult is the result returned by SourceDefaultInterface.Load().
// It contains all observers, verifiers, notifiers and detectors parsed from the V3 YAML configuration.
type SourceDefaultResult struct {
	Observers []*ObserverConfig
	Verifiers []*VerifierConfig
	Notifiers []*NotifierDefaultConfig
	Detectors []*DetectorDefaultConfig
}

// SourceDefaultInterface is the interface for V3 YAML-based configuration sources.
type SourceDefaultInterface interface {
	Name() string
	Load() (*SourceDefaultResult, error)
}
