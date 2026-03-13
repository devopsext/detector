package verifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"golang.org/x/sync/errgroup"
)

type QATestsOptions struct {
	URL              string
	Timeout          int
	Insecure         bool
	BusinessProcess  string
	AllureProjectId  string
	AllureLaunchName string
	AllureLaunchTags []string
	Priority         int
	SecsBoundary     int
	TestTimeout      int
	TestRetries      int
}

type QATestsRequest struct {
	BusinessProcess string              `json:"BisnessProcesses"`
	PytestParams    QATestsPytestParams `json:"PytestParams"`
	TaskParams      QATestsTaskParams   `json:"TaskParams"`
}

type QATestsPytestParams struct {
	Timeout      int    `json:"Timeout"`
	Retries      int    `json:"Retries"`
	Host         string `json:"Host"`
	ProxyCountry string `json:"ProxyCountry"`
}

type QATestsTaskParams struct {
	AllureForceNewLaunch bool     `json:"AllureForceNewLaunch"`
	AllureProjectId      string   `json:"AllureProjectId"`
	AllureLaunchName     string   `json:"AllureLaunchName"`
	AllureLaunchTags     []string `json:"AllureLaunchTags"`
	Priority             int      `json:"Priority"`
	SecsBoundary         int      `json:"SecsBoundary"`
}

type QATestsResponse struct {
	Allure interface{} `json:"allure"`
	Tasks  []QATask    `json:"tasks"`
}

type QATask struct {
	TaskID string         `json:"task_id"`
	Status string         `json:"status"`
	Allure []QATaskAllure `json:"allure"`
	Result QATaskResult   `json:"result"`
}

type QATaskAllure struct {
	LaunchId   string `json:"launch_id"`
	AllureLink string `json:"allure_link"`
}

type QATaskResult struct {
	Created  float64       `json:"created"`
	Duration float64       `json:"duration"`
	ExitCode int           `json:"exitcode"`
	Summary  QATestSummary `json:"summary"`
	Test     QATest        `json:"test"`
}

type QATestSummary struct {
	Passed     int `json:"passed"`
	Total      int `json:"total"`
	Collected  int `json:"collected"`
	Deselected int `json:"deselected"`
}

type QATest struct {
	Duration   float64  `json:"duration"`
	Scenario   string   `json:"scenario"`
	FailedStep string   `json:"failed_step"`
	Keywords   []string `json:"keywords"`
	Outcome    string   `json:"outcome"`
	PytestName string   `json:"pytest_name"`
}

type QATestsSummary struct {
	Country string
	Avg     float64
	Flags   map[common.VerifyStatusFlag]bool
}

type QATests struct {
	logger  sreCommon.Logger
	options *QATestsOptions
	client  *http.Client
	metrics *common.VerifierMetrics
}

const QATestsVerifierName = "QATests"
const QATestsEndpoint = "/run_tests_sync"

func (q *QATests) Name() string {
	return QATestsVerifierName
}

func (q *QATests) createHTTPClient() *http.Client {
	httpTimeout := q.options.Timeout
	if httpTimeout <= q.options.TestTimeout {
		httpTimeout = q.options.TestTimeout + 10
	}

	timeout := time.Duration(httpTimeout) * time.Second
	return &http.Client{
		Timeout: timeout,
	}
}

func (q *QATests) runQATest(host, country string) (*QATestsResponse, error) {
	// Record test start in metrics for each country
	if q.metrics != nil {
		domain := common.ExtractDomain(host)
		normalizedCountry := common.NormalizeCountryForMetrics(country)
		q.metrics.RecordTestStartByType("verifier", q.Name(), domain, normalizedCountry)
	}
	requestBody := QATestsRequest{
		BusinessProcess: q.options.BusinessProcess,
		PytestParams: QATestsPytestParams{
			Timeout:      q.options.TestTimeout,
			Retries:      q.options.TestRetries,
			Host:         host,
			ProxyCountry: strings.ToLower(country),
		},
		TaskParams: QATestsTaskParams{
			AllureForceNewLaunch: false,
			AllureProjectId:      q.options.AllureProjectId,
			AllureLaunchName:     q.options.AllureLaunchName,
			AllureLaunchTags:     q.options.AllureLaunchTags,
			Priority:             q.options.Priority,
			SecsBoundary:         q.options.SecsBoundary,
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		// Record error in metrics
		if q.metrics != nil {
			domain := common.ExtractDomain(host)
			normalizedCountry := common.NormalizeCountryForMetrics(country)
			q.metrics.RecordTestErrorByType("verifier", q.Name(), domain, normalizedCountry, "marshal_error", 0)
		}
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Form URL with path from constant
	requestURL := q.options.URL
	if !strings.HasSuffix(requestURL, QATestsEndpoint) {
		if strings.HasSuffix(requestURL, "/") {
			requestURL = requestURL + strings.TrimPrefix(QATestsEndpoint, "/")
		} else {
			requestURL = requestURL + QATestsEndpoint
		}
	}

	req, err := http.NewRequest("POST", requestURL, bytes.NewBuffer(jsonData))
	if err != nil {
		// Record error in metrics
		if q.metrics != nil {
			domain := common.ExtractDomain(host)
			normalizedCountry := common.NormalizeCountryForMetrics(country)
			q.metrics.RecordTestErrorByType("verifier", q.Name(), domain, normalizedCountry, "request_creation_error", 0)
		}
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := q.client.Do(req)
	if err != nil {
		// Record error in metrics
		if q.metrics != nil {
			domain := common.ExtractDomain(host)
			normalizedCountry := common.NormalizeCountryForMetrics(country)
			q.metrics.RecordTestErrorByType("verifier", q.Name(), domain, normalizedCountry, "request_execution_error", 0)
		}
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// Record error in metrics
		if q.metrics != nil {
			domain := common.ExtractDomain(host)
			normalizedCountry := common.NormalizeCountryForMetrics(country)
			q.metrics.RecordTestErrorByType("verifier", q.Name(), domain, normalizedCountry, "http_status_error", 0)
		}
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// Record error in metrics
		if q.metrics != nil {
			domain := common.ExtractDomain(host)
			normalizedCountry := common.NormalizeCountryForMetrics(country)
			q.metrics.RecordTestErrorByType("verifier", q.Name(), domain, normalizedCountry, "response_read_error", 0)
		}
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var qaResponse QATestsResponse
	err = json.Unmarshal(body, &qaResponse)
	if err != nil {
		// Record error in metrics
		if q.metrics != nil {
			domain := common.ExtractDomain(host)
			normalizedCountry := common.NormalizeCountryForMetrics(country)
			q.metrics.RecordTestErrorByType("verifier", q.Name(), domain, normalizedCountry, "unmarshal_error", 0)
		}
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	// HTTP request successful - metrics will be recorded in RecordTestResult

	// Probability is calculated and recorded separately in Verify method

	return &qaResponse, nil
}

func (q *QATests) processQATestResultsSummary(oe *common.ObserveEndpoint, results *[]QATestsResponse) (*[]QATestsSummary, error) {
	var rs []QATestsSummary

	for _, r := range *results {
		// Вычисляем availability на основе exitcode
		availability := float64(0.0)
		if len(r.Tasks) > 0 {
			task := r.Tasks[0]
			if task.Result.ExitCode == 0 {
				availability = 100.0
			} else {
				availability = 0.0
			}
		}

		// Probability = 100 - Availability
		probability := 100.0 - availability

		// Flags are not considered for this verifier
		var flags map[common.VerifyStatusFlag]bool = nil

		rs = append(rs, QATestsSummary{
			Country: "", // Country will be set later from request parameters
			Avg:     probability,
			Flags:   flags,
		})
	}

	return &rs, nil
}

func (q *QATests) Verify(or *common.ObserveResult) (*common.VerifyResult, error) {
	if or.Endpoints.IsEmpty() {
		return nil, errors.New("QATests verifier cannot process empty endpoints")
	}

	q.logger.Debug("QATests verifier is processing...")
	t1 := time.Now()

	g := &errgroup.Group{}
	m := &sync.Map{}

	for _, oe := range or.Endpoints.Items() {
		g.Go(func() error {
			uri := common.NormalizeURI(oe.URI)
			var qaResults []QATestsResponse
			var err error

			countries := slices.Collect(maps.Keys(oe.Countries))
			if len(countries) == 0 {
				return nil
			}
			scheme := common.URIScheme(uri)

			q.logger.Debug("QATests verifier is checking %s endpoint %s in countries %s", scheme, uri, countries)
			t1 := time.Now()

			// Collect QA test results for all countries
			for _, country := range countries {
				switch scheme {
				case common.URISchemeHttp, common.URISchemeHttps:
					host := oe.URI
					if utils.IsEmpty(common.URIScheme(uri)) {
						host = fmt.Sprintf("%s://%s", scheme, host)
					}

					qaResponse, err := q.runQATest(host, country)
					if err != nil {
						return fmt.Errorf("QATests verifier failed to run test: %s", err)
					}

					qaResults = append(qaResults, *qaResponse)
				default:
					return fmt.Errorf("QATests verifier has no support for %s endpoint %s in countries %s", scheme, uri, countries)
				}
			}

			q.logger.Debug("QATests verifier checked %s endpoint %s in %s in %s", scheme, uri, countries, time.Since(t1))

			if len(qaResults) == 0 {
				return nil
			}

			// Process results through processQATestResultsSummary
			summaries, err := q.processQATestResultsSummary(oe, &qaResults)
			if err != nil {
				return fmt.Errorf("QATests verifier failed to process results: %s", err)
			}

			ve := &common.VerifyEndpoint{
				URI:       uri,
				Countries: common.VerifyCountries{},
			}

			// Set country for each result
			for i, summary := range *summaries {
				if i < len(countries) {
					summary.Country = common.NormalizeCountry(countries[i])
				}

				vs := ve.Countries[summary.Country]
				if vs == nil {
					vs = &common.VerifyStatus{}
				}
				vs.Probability = &summary.Avg
				vs.Flags = summary.Flags
				ve.Countries[summary.Country] = vs
			}
			m.Store(nil, ve)
			return nil
		})
	}

	err := g.Wait()
	if err != nil {
		return nil, err
	}

	q.logger.Debug("QATests verifier spent %s", time.Since(t1))

	vs := common.VerifyEndpoints{}
	m.Range(func(key, value any) bool {
		e, ok := value.(*common.VerifyEndpoint)
		if !ok {
			return false
		}
		vs.Add(e)
		return true
	})

	r := &common.VerifyResult{
		Endpoints: vs,
	}
	return r, nil
}

// VerifyDefault implements common.VerifierDefaultInterface for the Default pipeline.
// TODO: implement actual verification logic for Default pipeline.
func (q *QATests) VerifyDefault(out *common.ObserveDefaultOutput) (*common.VerifyDefaultResult, error) {
	q.logger.Debug("QATests.VerifyDefault: not yet implemented")
	return &common.VerifyDefaultResult{}, nil
}

func NewQATests(options *QATestsOptions, observability *common.Observability, metrics *common.VerifierMetrics) *QATests {
	logger := observability.Logs()

	if utils.IsEmpty(options.URL) {
		logger.Debug("QATests verifier URL is not defined. Skipped.")
		return nil
	}

	qa := &QATests{
		logger:  logger,
		options: options,
		metrics: metrics,
	}

	qa.client = qa.createHTTPClient()

	return qa
}
