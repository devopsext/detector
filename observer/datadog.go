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
	metrics *common.VerifierMetrics
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

// datadogRawSeries holds the raw timeseries summary with all group tags as a map.
type datadogRawSeries struct {
	tags map[string]string
	Avg  float64
}

// timeseriesV2ToRaw converts a V2 timeseries response into raw label-keyed series.
// Unlike timeseriesV2ToData, it does NOT require specific URI/country tags — it captures all group tags.
func (d *Datadog) timeseriesV2ToRaw(resp *datadogV2.TimeseriesFormulaQueryResponse) []*datadogRawSeries {

	r := []*datadogRawSeries{}

	tr := resp.GetData()
	series := tr.Attributes.GetSeries()
	values := tr.Attributes.GetValues()

	if len(series) != len(values) {
		return r
	}

	for idx, s := range series {

		v := values[idx]
		if len(v) == 0 {
			continue
		}

		count := 0
		sum := float64(0.0)

		for _, p := range v {
			if p == nil {
				continue
			}
			count++
			sum += *p
		}

		if count == 0 {
			continue
		}

		// Parse all group tags into a map
		tags := make(map[string]string)
		for _, tagStr := range s.GroupTags {
			parts := strings.SplitN(tagStr, ":", 2)
			if len(parts) == 2 {
				tags[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		r = append(r, &datadogRawSeries{
			tags: tags,
			Avg:  sum / float64(count),
		})
	}
	return r
}

// getV2TimeseriesRaw fetches timeseries data and returns raw label-keyed series.
// Used by ObserveDefault for the Default pipeline.
func (d *Datadog) getV2TimeseriesRaw(query string, from, to time.Time) ([]*datadogRawSeries, error) {

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

	return d.timeseriesV2ToRaw(&resp), nil
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

func (d *Datadog) buildQuery(sr *common.SourceEndpointResult, query, tagUri string) string {

	from := ""
	for _, e := range sr.Endpoints.Items() {

		if e == nil {
			continue
		}

		uri := common.NormalizeURI(e.URI)
		if utils.IsEmpty(uri) {
			continue
		}

		filter := fmt.Sprintf("%s:%s", tagUri, uri)

		if !utils.IsEmpty(from) {
			from = fmt.Sprintf("%s OR %s", from, filter)
		} else {
			from = filter
		}
	}

	return fmt.Sprintf(query, from)
}

func (d *Datadog) Observe(sr *common.SourceEndpointResult) (*common.ObserveResult, error) {

	if sr.Endpoints.IsEmpty() {
		return nil, errors.New("Datadog observer cannot process empty endpoints")
	}

	d.logger.Debug("Datadog observer is processing...")

	// Record observer start in metrics - один запрос для всех доменов
	if d.metrics != nil {
		d.metrics.RecordTestStartByType("observer", "datadog", "datadog_api", "all")
	}

	var md DatadogMetricData

	if utils.FileExists(d.options.File) {

		d.logger.Debug("Datadog observer is loading data from %s", d.options.File)

		t1 := time.Now()

		mf, err := d.loadV1File(d.options.File)
		if err != nil {
			// Record file loading error in metrics
			if d.metrics != nil {
				d.metrics.RecordTestErrorByType("observer", "datadog", "datadog_file", "all", "file_loading_error", 0)
			}
			return nil, err
		}
		md = mf

		// Record successful file loading in metrics
		if d.metrics != nil {
			d.metrics.RecordTestSuccessByType("observer", "datadog", "datadog_file", "all", 0)
		}

		d.logger.Debug("Datadog observer spent %s", time.Since(t1))

	} else if !utils.IsEmpty(d.options.Query) {

		query := d.buildQuery(sr, d.options.Query, d.options.TagUri)
		d.logger.Debug("Datadog observer is requesting data by query: %s", query)

		from, to, err := d.getFromTo(d.options.Duration)
		if err != nil {
			return nil, err
		}
		d.logger.Debug("Datadog observer interval %d <=> %d", from.UnixMilli(), to.UnixMilli())

		t1 := time.Now()

		mf, err := d.getV2Timeseries(query, *from, *to, d.options.TagUri, d.options.TagCountry)
		if err != nil {
			// Record HTTP request error in metrics
			if d.metrics != nil {
				d.metrics.RecordTestErrorByType("observer", "datadog", "datadog_api", "all", "http_request_error", 0)
			}
			return nil, err
		}
		md = mf
		d.logger.Debug("Datadog observer spent %s", time.Since(t1))

		// Record successful HTTP request in metrics
		if d.metrics != nil {
			d.metrics.RecordTestSuccessByType("observer", "datadog", "datadog_api", "all", 0)
		}
	}

	d.logger.Debug("Datadog observer metrics found: %d", len(md))
	if len(md) == 0 {
		return nil, nil
	}

	es := common.ObserveEndpoints{}

	for _, e := range sr.Endpoints.Items() {

		if e == nil {
			continue
		}

		uri := common.NormalizeURI(e.URI)

		count := 0
		sum := float64(0.0)
		countries := make(common.ObserveCountries)

		for _, country := range e.Countries {

			normalizedCountry := common.NormalizeCountry(country)
			sm := d.firstURIbyCountry(md, uri, normalizedCountry)

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
			URI:       uri,
			Countries: countries,
			IPs:       e.IPs,
			Response:  e.Response,
		}
		es.Add(e)
	}

	r := &common.ObserveResult{
		Endpoints: es,
	}

	// HTTP запрос к Datadog API уже залогирован выше
	// Здесь больше не логируем метрики для каждого домена/страны

	return r, nil
}

// ObserveDefault implements common.ObserverDefault for the Default pipeline.
// It uses a pre-built query from ObserverConfig instead of building it from endpoint URIs.
func (d *Datadog) ObserveDefault(cfg *common.ObserverConfig) (*common.ObserveDefaultOutput, error) {

	if utils.IsEmpty(cfg.QueryDatadog) {
		return nil, fmt.Errorf("Datadog observer has no query_datadog in config %s", cfg.Name)
	}

	d.logger.Debug("Datadog observer (Default) is processing query: %s", cfg.QueryDatadog)

	from, to, err := d.getFromTo(d.options.Duration)
	if err != nil {
		return nil, err
	}
	d.logger.Debug("Datadog observer (Default) interval %d <=> %d", from.UnixMilli(), to.UnixMilli())

	md, err := d.getV2TimeseriesRaw(cfg.QueryDatadog, *from, *to)
	if err != nil {
		return nil, err
	}

	if len(md) == 0 {
		d.logger.Debug("Datadog observer (Default) found no metrics for query: %s", cfg.QueryDatadog)
		return nil, nil
	}

	out := &common.ObserveDefaultOutput{}
	for _, m := range md {
		// Build a labels map from all tag key:value pairs in the series
		labels := make(map[string]string)
		for k, v := range m.tags {
			labels[k] = v
		}
		out.Items = append(out.Items, &common.ObserveDefaultItem{
			Labels: labels,
			Value:  m.Avg,
		})
	}

	d.logger.Debug("Datadog observer (Default) found %d series", len(out.Items))
	return out, nil
}

func NewDatadog(options *DatadogOptions, observability *common.Observability, metrics *common.VerifierMetrics) *Datadog {

	logger := observability.Logs()

	if utils.IsEmpty(options.Site) {
		logger.Debug("Datdog observer site is not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.TagUri) || utils.IsEmpty(options.TagCountry) {
		logger.Debug("Datdog observer tags are not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.Query) && utils.IsEmpty(options.File) {
		logger.Debug("Datdog observer query or file are not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.Duration) {
		logger.Debug("Datdog observer duration is not defined. Skipped.")
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
		metrics: metrics,
	}
}
