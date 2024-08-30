package observer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
)

type DatadogOptions struct {
	Site       string
	ApiKey     string
	AppKey     string
	TagUri     string
	TagCountry string
	Query      string
	File       string
	Min        float64
	Max        float64
	Duration   string
	Timeout    string
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
	apiV1   *datadogV1.MetricsApi
	apiV2   *datadogV2.MetricsApi
	ctx     context.Context
}

const ObserverDatadogName = "Datadog"

func (d *Datadog) Name() string {
	return ObserverDatadogName
}

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

func (d *Datadog) loadV1File(file string) (DatadogMetricData, error) {

	data, err := utils.Content(file)
	if err != nil {
		return nil, err
	}

	var resp datadogV1.MetricsQueryResponse
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, errors.New(*resp.Error)
	}

	if !resp.HasSeries() {
		return nil, nil
	}

	return d.timeseriesV1ToData(&resp, d.options.Min, d.options.Max), nil
}

func (d *Datadog) getV1Timeseries(query string, from, to time.Time) (DatadogMetricData, error) {

	t1 := from.Unix()
	t2 := to.Unix()

	resp, _, err := d.apiV1.QueryMetrics(d.ctx, t1, t2, query)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, errors.New(*resp.Error)
	}

	if !resp.HasSeries() {
		return nil, nil
	}

	return d.timeseriesV1ToData(&resp, d.options.Min, d.options.Max), nil
}

func (d *Datadog) timeseriesV2ToData(resp *datadogV2.TimeseriesFormulaQueryResponse, minLimit, maxLimit float64, tagUri, tagCountry string) DatadogMetricData {

	r := DatadogMetricData{}

	tr := resp.GetData()

	series := tr.Attributes.GetSeries()
	values := tr.Attributes.GetValues()

	if len(series) != len(values) {
		return r
	}

	for idx, s := range series {

		v := values[idx]

		uri := d.getTagValue(s.GroupTags, tagUri)
		if utils.IsEmpty(uri) {
			continue
		}
		country := d.getTagValue(s.GroupTags, tagCountry)
		if utils.IsEmpty(country) {
			continue
		}

		if len(v) == 0 {
			continue
		}

		count := 0
		sum := float64(0.0)

		// swap min and max
		min := maxLimit
		max := minLimit

		for _, p := range v {

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

func (d *Datadog) getV2Timeseries(query string, from, to time.Time, tagUri, tagCountry string) (DatadogMetricData, error) {

	t1 := from.UnixMilli()
	t2 := to.UnixMilli()

	name := "a"
	squery := datadogV2.TimeseriesQuery{
		MetricsTimeseriesQuery: &datadogV2.MetricsTimeseriesQuery{
			Name:       &name,
			DataSource: datadogV2.METRICSDATASOURCE_METRICS,
			Query:      query,
		},
	}

	body := datadogV2.TimeseriesFormulaQueryRequest{
		Data: datadogV2.TimeseriesFormulaRequest{
			Attributes: datadogV2.TimeseriesFormulaRequestAttributes{
				From:    t1,
				To:      t2,
				Queries: []datadogV2.TimeseriesQuery{squery},
			},
			Type: datadogV2.TIMESERIESFORMULAREQUESTTYPE_TIMESERIES_REQUEST,
		},
	}

	resp, _, err := d.apiV2.QueryTimeseriesData(d.ctx, body)
	if err != nil {
		return nil, err
	}

	if resp.HasErrors() {
		return nil, errors.New(*resp.Errors)
	}

	if !resp.HasData() {
		return nil, nil
	}

	return d.timeseriesV2ToData(&resp, d.options.Min, d.options.Max, tagUri, tagCountry), nil
}

func (d *Datadog) getFromTo(duration string) (*time.Time, *time.Time, error) {

	dur, err := time.ParseDuration(duration)
	if err != nil {
		return nil, nil, err
	}

	start := time.Now()
	end := start.Add(dur)

	if start.UnixNano() > end.UnixNano() {
		t := end
		end = start
		start = t
	}

	return &start, &end, nil
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

func (d *Datadog) buildQuery(sr *common.SourceResult, query, tagUri string) string {

	from := ""
	for _, e := range sr.Endpoints {

		filter := fmt.Sprintf("%s:%s", tagUri, e.URI)

		if !utils.IsEmpty(from) {
			from = fmt.Sprintf("%s OR %s", from, filter)
		} else {
			from = filter
		}
	}

	return fmt.Sprintf(query, from)
}

func (d *Datadog) Observe(sr *common.SourceResult) (*common.ObserveResult, error) {

	if len(sr.Endpoints) == 0 {
		return nil, errors.New("Datadog cannot process empty endpoints")
	}

	var md DatadogMetricData

	if utils.FileExists(d.options.File) {

		mf, err := d.loadV1File(d.options.File)
		if err != nil {
			return nil, err
		}
		md = mf
	} else if !utils.IsEmpty(d.options.Query) {

		query := d.buildQuery(sr, d.options.Query, d.options.TagUri)
		d.logger.Debug("Datadog query: %s", query)

		from, to, err := d.getFromTo(d.options.Duration)
		if err != nil {
			return nil, err
		}
		d.logger.Debug("Datadog interval %d <=> %d", from.UnixMilli(), to.UnixMilli())

		mf, err := d.getV2Timeseries(query, *from, *to, d.options.TagUri, d.options.TagCountry)
		if err != nil {
			return nil, err
		}
		md = mf
	}

	d.logger.Debug("Datadog metrics found: %d", len(md))
	if len(md) == 0 {
		return nil, nil
	}

	es := common.ObserveEndpoints{}

	for _, e := range sr.Endpoints {

		uri := common.NormalizeURI(e.URI)

		count := 0
		sum := float64(0.0)
		countries := make(common.ObserveCountries)

		for _, c := range e.Countries {

			country := common.NormalizeCountry(c)
			sm := d.firstURIbyCountry(md, uri, country)

			if sm == nil {
				countries[country] = nil
				continue
			}

			count = count + 1
			sum = sum + sm.Avg
			savg := d.options.Max - sm.Avg
			countries[country] = &savg
		}

		if count == 0 {
			continue
		}

		e := &common.ObserveEndpoint{
			URI:            uri,
			Countries:      countries,
			SourceEndpoint: e,
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

	if utils.IsEmpty(options.Query) && utils.IsEmpty(options.File) {
		logger.Debug("Datdog query or file are not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.Duration) {
		logger.Debug("Datdog duration is not defined. Skipped.")
		return nil
	}

	config := datadog.NewConfiguration()
	config.SetUnstableOperationEnabled("v2.QueryScalarData", true)
	config.SetUnstableOperationEnabled("v2.QueryTimeseriesData", true)

	client := datadog.NewAPIClient(config)

	if !utils.IsEmpty(options.Timeout) {
		d, err := time.ParseDuration(options.Timeout)
		if err == nil && config.HTTPClient != nil {
			config.HTTPClient.Timeout = d
		}
	}

	apiV1 := datadogV1.NewMetricsApi(client)
	apiV2 := datadogV2.NewMetricsApi(client)

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
				Key: options.AppKey,
			},
			"apiKeyAuth": {
				Key: options.ApiKey,
			},
		},
	)

	return &Datadog{
		options: options,
		logger:  logger,
		apiV1:   apiV1,
		apiV2:   apiV2,
		ctx:     ctx,
	}
}
