package observer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
)

type DatadogOptions struct {
	Site       string
	Key        string
	TagUri     string
	TagCountry string
	Query      string
	File       string
	Min        float64
	Max        float64
}

type DatadogMetricSummary struct {
	URI     string
	Country string
	Avg     float64
	Min     float64
	Max     float64
}

type DatadogMetricData = []*DatadogMetricSummary

type Datadog struct {
	options *DatadogOptions
	logger  sreCommon.Logger
	api     *datadogV2.MetricsApi
	ctx     context.Context
}

const ObserverDatadogName = "Datadog"

func (d *Datadog) Name() string {
	return ObserverDatadogName
}

/*
func (d *Datadog) getAggregator(query string) datadogV2.MetricsAggregator {

	def := datadogV2.METRICSAGGREGATOR_AVG

	prefix := ""
	arr := strings.Split(query, ":")
	if len(arr) > 1 {
		prefix = strings.TrimSpace(arr[0])
	}

	if !utils.IsEmpty(prefix) {
		return datadogV2.MetricsAggregator(prefix)
	}

	return def
}

func (d *Datadog) queryScalarData(from, to, query string) (*datadogV2.ScalarFormulaQueryResponse, error) {

	t1 := int64(1724158716000)
	t2 := int64(1724158762000)

	squery := datadogV2.ScalarQuery{
		MetricsScalarQuery: &datadogV2.MetricsScalarQuery{
			Aggregator: d.getAggregator(query),
			DataSource: datadogV2.METRICSDATASOURCE_METRICS,
			Query:      query,
		},
	}

	body := datadogV2.ScalarFormulaQueryRequest{
		Data: datadogV2.ScalarFormulaRequest{
			Attributes: datadogV2.ScalarFormulaRequestAttributes{
				From:    t1,
				To:      t2,
				Queries: []datadogV2.ScalarQuery{squery},
			},
			Type: datadogV2.SCALARFORMULAREQUESTTYPE_SCALAR_REQUEST,
		},
	}

	sr, r, err := d.api.QueryScalarData(d.ctx, body)
	if err != nil {
		return nil, err
	}

	if r.StatusCode != 200 {
		return nil, fmt.Errorf("Datadog query scalar data status %s [%d]", r.Status, r.StatusCode)
	}
	return &sr, nil
}

func (d *Datadog) queryTimeseriesData(from, to, query string) (*datadogV2.TimeseriesFormulaQueryResponse, error) {

	t1 := int64(1724158716000)
	t2 := int64(1724158762000)

	squery := datadogV2.TimeseriesQuery{
		MetricsTimeseriesQuery: &datadogV2.MetricsTimeseriesQuery{
			DataSource: datadogV2.METRICSDATASOURCE_METRICS,
			Query:      query,
		},
	}

	body := datadogV2.TimeseriesFormulaQueryRequest{
		Data: datadogV2.TimeseriesFormulaRequest{
			Attributes: datadogV2.TimeseriesFormulaRequestAttributes{
				Formulas: []datadogV2.QueryFormula{
					{
						Formula: "a",
						Limit: &datadogV2.FormulaLimit{
							Count: datadog.PtrInt32(10),
							Order: datadogV2.QUERYSORTORDER_DESC.Ptr(),
						},
					},
				},
				From:    t1,
				To:      t2,
				Queries: []datadogV2.TimeseriesQuery{squery},
			},
			Type: datadogV2.TIMESERIESFORMULAREQUESTTYPE_TIMESERIES_REQUEST,
		},
	}

	sr, r, err := d.api.QueryTimeseriesData(d.ctx, body)
	if err != nil {
		return nil, err
	}

	if r.StatusCode != 200 {
		return nil, fmt.Errorf("Datadog query timeseries data status %s [%d]", r.Status, r.StatusCode)
	}
	return &sr, nil
}

	dsr, err := d.queryTimeseriesData("", "", d.options.Query)
	if err != nil {
		return nil, err
	}

	if !dsr.HasData() {
		return nil, errors.New("Datadog query has no data")
	}

	d.logger.Debug("Datadog found elements %d", len(dsr.Data.UnparsedObject))

*/

func (d *Datadog) getTagValue(ts []string, tag string) string {

	r := ""
	for _, t := range ts {

		name := ""
		value := ""
		arr := strings.Split(t, ":")
		if len(arr) < 2 {
			continue
		}
		name = strings.TrimSpace(arr[0])
		value = strings.TrimSpace(arr[1])

		if tag == name {
			r = value
		}
	}
	return r
}

func (d *Datadog) timeseriesV1ToData(resp *datadogV1.MetricsQueryResponse, minLimit, maxLimit float64) DatadogMetricData {

	r := DatadogMetricData{}

	for _, v := range resp.Series {

		uri := d.getTagValue(v.TagSet, d.options.TagUri)
		if utils.IsEmpty(uri) {
			continue
		}
		country := d.getTagValue(v.TagSet, d.options.TagCountry)
		if utils.IsEmpty(country) {
			continue
		}

		if !v.HasPointlist() {
			continue
		}

		count := 0
		sum := float64(0.0)

		// swap min and max
		min := maxLimit
		max := minLimit

		for _, pp := range v.GetPointlist() {

			if len(pp) < 2 {
				continue
			}
			// use only second cause its timeseries
			p := pp[1]
			if p == nil {
				continue
			}
			count = count + 1
			sum = sum + *p

			if *p > max {
				max = *p
			}
			if *p < min {
				min = *p
			}
		}

		avg := sum / float64(count)

		r = append(r, &DatadogMetricSummary{
			URI:     common.NormalizeURI(uri),
			Country: common.NormalizeCountry(country),
			Avg:     avg,
			Min:     min,
			Max:     max,
		})
	}
	return r
}

func (d *Datadog) loadFile(file string) (DatadogMetricData, error) {

	var resp datadogV1.MetricsQueryResponse
	err := json.Unmarshal([]byte(file), &resp)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, errors.New(*resp.Error)
	}

	if len(resp.Series) == 0 {
		return nil, nil
	}

	return d.timeseriesV1ToData(&resp, d.options.Min, d.options.Max), nil
}

func (d *Datadog) filterURIbyCountry(md DatadogMetricData, uri, country string) DatadogMetricData {

	r := DatadogMetricData{}
	for _, k := range md {
		if k.URI == uri && k.Country == country {
			r = append(r, k)
		}
	}
	return r
}

func (d *Datadog) firstURIbyCountry(md DatadogMetricData, uri, country string) *DatadogMetricSummary {

	r := d.filterURIbyCountry(md, uri, country)
	if len(r) > 0 {
		return r[0]
	}
	return nil
}

func (d *Datadog) Observe(sr *common.SourceResult) (*common.ObserveResult, error) {

	if len(sr.Endpoints) == 0 {
		return nil, errors.New("Datadog cannot process empty endpoints")
	}

	query := d.options.Query // need to build it based on field and query from options

	d.logger.Debug("Datadog query: %s", query)

	var md DatadogMetricData

	if !utils.IsEmpty(d.options.File) {
		mf, err := d.loadFile(d.options.File)
		if err != nil {
			return nil, err
		}
		md = mf
	}

	d.logger.Debug("Datadog metrics found: %d", len(md))
	if len(md) == 0 {
		return nil, nil
	}

	es := []*common.ObserveEndpoint{}

	for _, e := range sr.Endpoints {

		uri := common.NormalizeURI(e.URI)

		count := 0
		sum := float64(0.0)
		countries := make(map[string]*common.Probability)

		for _, c := range e.Countries {

			country := common.NormalizeCountry(c)
			sm := d.firstURIbyCountry(md, uri, country)

			if sm == nil {
				countries[country] = nil
				continue
			}

			count = count + 1
			sum = sum + sm.Avg
			countries[country] = &sm.Avg
		}

		if count == 0 {
			continue
		}

		avg := sum / float64(count)

		e := &common.ObserveEndpoint{
			URI:         uri,
			Countries:   countries,
			Probability: d.options.Max - avg,
		}
		es = append(es, e)
	}

	r := &common.ObserveResult{
		Observer:     d,
		SourceResult: sr,
		Endpoints:    es,
	}
	return r, nil
}

func NewDatadog(options *DatadogOptions, observability *common.Observability) *Datadog {

	logger := observability.Logs()

	if utils.IsEmpty(options.Site) {
		logger.Debug("Datdog site is not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.TagUri) || utils.IsEmpty(options.TagCountry) {
		logger.Debug("Datdog tags are not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("Datdog query is not defined. Skipped.")
		return nil
	} else if utils.IsEmpty(options.File) {
		logger.Debug("Datdog file is not defined. Skipped.")
		return nil
	}

	config := datadog.NewConfiguration()
	config.SetUnstableOperationEnabled("v2.QueryScalarData", true)
	config.SetUnstableOperationEnabled("v2.QueryTimeseriesData", true)

	client := datadog.NewAPIClient(config)
	api := datadogV2.NewMetricsApi(client)

	ctx := context.WithValue(
		context.Background(),
		datadog.ContextServerVariables,
		map[string]string{
			"site": options.Site,
		},
	)

	ctx = context.WithValue(
		ctx,
		datadog.ContextAPIKeys,
		map[string]datadog.APIKey{
			"appKeyAuth": {
				Key: options.Key,
			},
			"apiKeyAuth": {
				Key: options.Key,
			},
		},
	)

	return &Datadog{
		options: options,
		logger:  logger,
		api:     api,
		ctx:     ctx,
	}
}
