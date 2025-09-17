package common

import (
	"strings"
	"sync"

	sreCommon "github.com/devopsext/sre/common"
)

type VerifierMetrics struct {
	metrics *sreCommon.Metrics
	mutex   sync.RWMutex
}

// Metrics for verifiers - use separate metrics for each combination of labels

func NewVerifierMetrics(metrics *sreCommon.Metrics) *VerifierMetrics {
	if metrics == nil {
		return nil
	}

	vm := &VerifierMetrics{
		metrics: metrics,
	}

	return vm
}

// RecordTestStart records the start of the test
func (vm *VerifierMetrics) RecordTestStart(verifier, domain, country string) {
	if vm == nil || vm.metrics == nil {
		return
	}

	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	// Create a metric with specific labels
	counter := vm.metrics.Counter(
		"verifier",
		"detector_tests_total",
		"Total number of verifier tests executed",
		sreCommon.Labels{
			"verifier": verifier,
			"domain":   domain,
			"country":  country,
			"status":   "started",
		},
	)
	counter.Inc()
}

// RecordTestSuccess records the successful execution of the test
func (vm *VerifierMetrics) RecordTestSuccess(verifier, domain, country string, duration float64) {
	if vm == nil || vm.metrics == nil {
		return
	}

	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	// Create a metric for successful tests
	successCounter := vm.metrics.Counter(
		"verifier",
		"detector_tests_success",
		"Number of successful verifier tests",
		sreCommon.Labels{
			"verifier": verifier,
			"domain":   domain,
			"country":  country,
		},
	)
	successCounter.Inc()

	// Create a metric for the total number of tests
	totalCounter := vm.metrics.Counter(
		"verifier",
		"detector_tests_total",
		"Total number of verifier tests executed",
		sreCommon.Labels{
			"verifier": verifier,
			"domain":   domain,
			"country":  country,
			"status":   "success",
		},
	)
	totalCounter.Inc()
}

// RecordTestError records the error of the test
func (vm *VerifierMetrics) RecordTestError(verifier, domain, country, errorType string, duration float64) {
	if vm == nil || vm.metrics == nil {
		return
	}

	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	// Create a metric for errors
	errorCounter := vm.metrics.Counter(
		"verifier",
		"detector_tests_error",
		"Number of failed verifier tests",
		sreCommon.Labels{
			"verifier":   verifier,
			"domain":     domain,
			"country":    country,
			"error_type": errorType,
		},
	)
	errorCounter.Inc()

	// Create a metric for the total number of tests
	totalCounter := vm.metrics.Counter(
		"verifier",
		"detector_tests_total",
		"Total number of verifier tests executed",
		sreCommon.Labels{
			"verifier": verifier,
			"domain":   domain,
			"country":  country,
			"status":   "error",
		},
	)
	totalCounter.Inc()
}

// RecordTestResult records the result of the test with probability
func (vm *VerifierMetrics) RecordTestResult(verifier, domain, country string, probability float64, duration float64) {
	if vm == nil || vm.metrics == nil {
		return
	}

	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	// Determine the status based on probability
	status := "success"
	if probability > 0 {
		status = "problem"
	}

	// Create a metric for the total number of tests
	totalCounter := vm.metrics.Counter(
		"verifier",
		"detector_tests_total",
		"Total number of verifier tests executed",
		sreCommon.Labels{
			"verifier": verifier,
			"domain":   domain,
			"country":  country,
			"status":   status,
		},
	)
	totalCounter.Inc()

	// Record success/error for compatibility
	if probability == 0 {
		successCounter := vm.metrics.Counter(
			"verifier",
			"detector_tests_success",
			"Number of successful verifier tests",
			sreCommon.Labels{
				"verifier": verifier,
				"domain":   domain,
				"country":  country,
			},
		)
		successCounter.Inc()
	} else {
		errorCounter := vm.metrics.Counter(
			"verifier",
			"detector_tests_error",
			"Number of failed verifier tests",
			sreCommon.Labels{
				"verifier":   verifier,
				"domain":     domain,
				"country":    country,
				"error_type": "problem_detected",
			},
		)
		errorCounter.Inc()
	}

	// Record the current probability in gauge
	probabilityGauge := vm.metrics.Gauge(
		"verifier",
		"detector_tests_probability",
		"Current probability of problems detected",
		sreCommon.Labels{
			"verifier": verifier,
			"domain":   domain,
			"country":  country,
		},
	)
	probabilityGauge.Set(probability * 100)
}

// GetMetrics returns the metrics object for direct access
func (vm *VerifierMetrics) GetMetrics() *sreCommon.Metrics {
	return vm.metrics
}

// Helper functions for extracting the domain from URI
func ExtractDomain(uri string) string {
	// Simplified logic for extracting the domain
	// Can be expanded if necessary
	if uri == "" {
		return "unknown"
	}

	// Remove the protocol
	if idx := strings.Index(uri, "://"); idx != -1 {
		uri = uri[idx+3:]
	}

	// Remove the path
	if idx := strings.Index(uri, "/"); idx != -1 {
		uri = uri[:idx]
	}

	// Remove the port
	if idx := strings.Index(uri, ":"); idx != -1 {
		uri = uri[:idx]
	}

	if uri == "" {
		return "unknown"
	}

	return uri
}

// Helper function for normalizing the country
func NormalizeCountryForMetrics(country string) string {
	if country == "" {
		return "unknown"
	}
	// Simple normalization - convert to lowercase
	return strings.ToLower(country)
}
