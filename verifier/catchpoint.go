package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	//country "github.com/mikekonan/go-countries"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsCommon "github.com/devopsext/tools/common"
	vendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
	"github.com/jinzhu/copier"
	"golang.org/x/sync/errgroup"
)

type CatchpointOptions struct {
	vendors.CatchpointOptions
	vendors.CatchpointSearchNodesWithOptions
	TestID             string
	PollTimeout        int
	PollDelay          int
	InstantTestType    int
	HTTPMethodType     int
	MonitorType        int
	ResponseReportFile string
}

type CatchpointSummary struct {
	Country string
	Avg     float64
	Flags   map[common.VerifyStatusFlag]bool
}

type Catchpoint struct {
	logger  sreCommon.Logger
	options *CatchpointOptions
	client  *vendors.Catchpoint
	metrics *common.VerifierMetrics
}

const CatchpointVerifierName = "Catchpoint"

func (c *Catchpoint) Name() string {
	return CatchpointVerifierName
}

func (c *Catchpoint) cloneCatchpointOptions(opts vendors.CatchpointOptions, token string) vendors.CatchpointOptions {

	r := vendors.CatchpointOptions{}
	copier.Copy(&r, &opts)
	r.APIToken = token
	return r
}

func (c *Catchpoint) createIstantTest(token, url string, nodeIDs []*vendors.Node) (*vendors.CatchpointIstantTestResponse, error) {

	opts := c.cloneCatchpointOptions(c.options.CatchpointOptions, token)
	var nodesStr string
	for _, n := range nodeIDs {
		nodesStr = nodesStr + strconv.Itoa(n.ID) + ","
	}
	nodesStr = nodesStr[:len(nodesStr)-1]

	createOpts := vendors.CatchpointInstantTestOptions{
		URL:             url,
		NodesIds:        nodesStr,
		HTTPMethodType:  c.options.HTTPMethodType,
		InstantTestType: c.options.InstantTestType,
		MonitorType:     c.options.MonitorType,
		OnDemand:        true,
	}

	d, err := c.client.CustomInstantTest(opts, createOpts)
	if err != nil {
		return nil, c.client.CheckError(d, err)
	}

	r := vendors.CatchpointIstantTestResponse{}
	err = json.Unmarshal(d, &r)
	if err != nil {
		c.logger.Debug("Catchpoint verifier. CreateIstantTest. cannot unmarshal InstantTest")
		return nil, err
	}

	return &r, nil
}

func (c *Catchpoint) searchNodesWithOptions(opts vendors.CatchpointOptions, createOpts vendors.CatchpointSearchNodesWithOptions) (*vendors.CatchpointSearchNodesWithOptionsResponse, error) {
	ctr := toolsCommon.CountryByShort(createOpts.Country)
	createOpts.Country = ctr
	d, err := c.client.CustomSearchNodesWithOptions(opts, createOpts)
	if err != nil {
		c.logger.Debug("Catchpoint verifier. SearchNodesWithOptions. cannot search nodes")
		return nil, c.client.CheckError(d, err)
	}

	r := vendors.CatchpointSearchNodesWithOptionsResponse{}
	err = json.Unmarshal(d, &r)
	if err != nil {
		c.logger.Debug("Catchpoint verifier. SearchNodesWithOptions. cannot unmarshal nodes")
		return nil, err
	}

	return &r, nil
}

func (c *Catchpoint) waitPollSuccessOrCancel(ctx context.Context, token string, testID int, Nodes []*vendors.Node) bool {

	var nodes []int
	for _, n := range Nodes {
		nodes = append(nodes, n.ID)
	}

	var (
		wg      sync.WaitGroup
		results = make(chan bool, len(nodes))
		mu      sync.Mutex
	)

	strTestId := strconv.Itoa(testID)

	for _, nodeID := range nodes {
		wg.Add(1)

		go func(ctx context.Context, nodeID int) {
			defer wg.Done()

			opts := c.cloneCatchpointOptions(c.options.CatchpointOptions, token)
			t := time.Duration(c.options.PollDelay) * time.Second

			for {
				select {
				case <-ctx.Done():
					mu.Lock()
					results <- false
					mu.Unlock()
					return
				case <-time.After(t):

					d, err := c.client.CustomGetInstantTestResult(opts, strTestId, nodeID)
					err = c.client.CheckError(d, err)
					if err != nil {
						c.logger.Debug(err)
						continue
					}

					r := vendors.CatchpointInstantTestResultReponse{}
					err = json.Unmarshal(d, &r)
					if err != nil {
						c.logger.Debug("Catchpoint verifier. WaitingPoll. cannot unmarshal InstantTest result")
						continue
					}
					c.logger.Debug("Catchpoint verifier. Check status of %v InstantTest for [%v]%s Node", r.Data.InstantTestRecord.ID, r.Data.InstantTestRecord.Node.ID, r.Data.InstantTestRecord.Node.Name)

					if r.Data.InstantTestRecord.TestResult != nil {
						mu.Lock()
						results <- true
						mu.Unlock()
						return
					}
					continue
				}
			}
		}(ctx, nodeID)
	}

	wg.Wait()
	close(results)

	for result := range results {
		if result {
			return true
		}
	}
	return false
}

func (c *Catchpoint) getLogReport(token string, testID int, nodes []*vendors.Node) (*[]vendors.CatchpointInstantTestResultReponse, error) {

	var reportOpts []vendors.CatchpointInstantTestResultReponse
	strTestId := strconv.Itoa(testID)
	opts := c.cloneCatchpointOptions(c.options.CatchpointOptions, token)

	for _, node := range nodes {

		d, err := c.client.CustomGetInstantTestResult(opts, strTestId, node.ID)
		if err != nil {
			return nil, c.client.CheckError(d, err)
		}
		r := vendors.CatchpointInstantTestResultReponse{}
		err = json.Unmarshal(d, &r)
		if err != nil {
			c.logger.Debug("Catchpoint verifier. GetLogReport. cannot unmarshal InstantTest result")
			return nil, err
		}
		r.Data.InstantTestRecord.Node.ID = node.ID
		r.Data.InstantTestRecord.Node.Country = node.Country
		r.Data.InstantTestRecord.Node.Name = node.Name
		reportOpts = append(reportOpts, r)

	}
	return &reportOpts, nil
}

func (c *Catchpoint) verifyHttp(oe *common.ObserveEndpoint, token, scheme string, countries []string) (*[]vendors.CatchpointInstantTestResultReponse, error) {
	// Record test start in metrics for each country
	if c.metrics != nil {
		domain := common.ExtractDomain(oe.URI)
		for _, country := range countries {
			normalizedCountry := common.NormalizeCountryForMetrics(country)
			c.metrics.RecordTestStart(c.Name(), domain, normalizedCountry)
		}
	}

	u, err := url.Parse(oe.URI)
	if err != nil {
		// Record error parsing URL in metrics
		if c.metrics != nil {
			domain := common.ExtractDomain(oe.URI)
			for _, country := range countries {
				normalizedCountry := common.NormalizeCountryForMetrics(country)
				c.metrics.RecordTestError(c.Name(), domain, normalizedCountry, "url_parse_error", 0)
			}
		}
		return nil, err
	}

	murl := oe.URI
	if utils.IsEmpty(u.Scheme) {
		murl = fmt.Sprintf("%s://%s", scheme, murl)
	}

	var nodes []*vendors.Node
	opts := c.cloneCatchpointOptions(c.options.CatchpointOptions, token)
	nodesOpts := vendors.CatchpointSearchNodesWithOptions{
		Targeted:    false,
		Active:      true,
		Paused:      false,
		NetworkType: 0,
		IPv6:        false,
		PageNumber:  c.options.PageNumber,
		PageSize:    c.options.PageSize,
	}

	c.logger.Debug("Catchpoint verifier is searching Nodes in %s for InstantTest for endpoint %s...", countries, oe.URI)
	var d *vendors.CatchpointSearchNodesWithOptionsResponse
	for _, country := range countries {
		nodesOpts.Country = country
		d, err = c.searchNodesWithOptions(opts, nodesOpts)
		if err != nil {
			return nil, err
		}
		for _, n := range *d.Data.Nodes {
			nodes = append(nodes, &vendors.Node{
				ID:   n.ID,
				Name: n.Name,
				Country: &vendors.CatchpointCountry{
					Name: n.Country.Name,
				},
			})

		}
	}

	c.logger.Debug("Catchpoint verifier is creating InstantTest for endpoint %s in countries %s...", oe.URI, countries)
	wmr, err := c.createIstantTest(token, murl, nodes)
	if err != nil {
		return nil, err
	}

	var cancel context.CancelFunc
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.options.PollTimeout)*time.Second)
	defer cancel()

	var lrr *[]vendors.CatchpointInstantTestResultReponse
	var lerr error

	c.logger.Debug("Catchpoint verifier is waiting InstantTest %v for %s...", wmr.Data.ID, murl)
	c.waitPollSuccessOrCancel(ctx, token, wmr.Data.ID, nodes)

	c.logger.Debug("Catchpoint verifier completed InstantTest %v for %s...", wmr.Data.ID, murl)
	lr, err := c.getLogReport(token, wmr.Data.ID, nodes)
	if err != nil {
		lerr = err
	} else {
		lrr = lr
	}

	if lerr != nil {
		// Record error in metrics
		if c.metrics != nil {
			domain := common.ExtractDomain(oe.URI)
			for _, country := range countries {
				normalizedCountry := common.NormalizeCountryForMetrics(country)
				c.metrics.RecordTestError(c.Name(), domain, normalizedCountry, "log_report_error", 0)
			}
		}
		return nil, lerr
	}

	if lrr == nil {
		// Record error in metrics
		if c.metrics != nil {
			domain := common.ExtractDomain(oe.URI)
			for _, country := range countries {
				normalizedCountry := common.NormalizeCountryForMetrics(country)
				c.metrics.RecordTestError(c.Name(), domain, normalizedCountry, "empty_result", 0)
			}
		}
		return nil, nil
	}

	return lrr, nil
}

func (c *Catchpoint) processInstantTestResultSummary(oe *common.ObserveEndpoint, results *[]vendors.CatchpointInstantTestResultReponse) (*[]CatchpointSummary, error) {

	c.logger.Debug("Catchpoint verifier. processInstantTestResultSummary. Processing %d results for endpoint %s", len(*results), oe.URI)

	var rs []CatchpointSummary

	type summary struct {
		availability float64
		flags        common.VerifyStatusFlags
	}

	response := oe.Response

	var reCode *regexp.Regexp
	if response != nil && !utils.IsEmpty(response.Code) {
		reCode, _ = regexp.Compile(response.Code)
	}

	reIPs := make(map[string]*regexp.Regexp)
	for _, ip := range oe.IPs {
		reIP, _ := regexp.Compile(ip)
		if reIP == nil {
			continue
		}
		reIPs[ip] = reIP
	}

	m := make(map[string][]summary)

	for _, r := range *results {

		var Availability *float64
		var avbIndex int
		country := toolsCommon.CountryShort(r.Data.InstantTestRecord.Node.Country.Name)
		c.logger.Debug("Catchpoint verifier. processInstantTestResultSummary. Processing result for country %s, node %s", country, r.Data.InstantTestRecord.Node.Name)
		sm := m[country]
		if sm == nil {
			sm = []summary{}
		}

		for _, i := range *r.Data.InstantTestRecord.TestResult.Hosts.Fields {
			if i.Name == "% Availability" {
				avbIndex = i.Index
			}
		}
		for _, h := range *r.Data.InstantTestRecord.TestResult.Hosts.Metrics {
			if h.HostName == oe.URI {
				value := float64(h.Items[avbIndex])
				Availability = &value
			}
		}

		flags := make(common.VerifyStatusFlags)

		var reIP string
		if len(oe.IPs) > 0 {
			exists := false
			for _, v := range reIPs {
				for _, wr := range *r.Data.InstantTestRecord.TestResult.WebRecords.Items {
					if wr.NavigationUrl.Host == oe.URI {
						reIP = wr.IPAddess
						break
					}
				}
				if v.MatchString(reIP) {
					exists = true
					break
				}
			}
			flags[common.VerifyStatusFlagWrongIPAddress] = !exists
		}

		if reCode != nil {
			for _, wr := range *r.Data.InstantTestRecord.TestResult.WebRecords.Items {
				if wr.NavigationUrl.Host == oe.URI {
					if !reCode.MatchString(strconv.Itoa(wr.ResponseCode)) {
						flags[common.VerifyStatusFlagWrongResponseCode] = true
					}
					break
				}
			}

		}

		sm = append(sm, summary{
			availability: *Availability,
			flags:        flags,
		})
		m[country] = sm
	}

	for k, v := range m {

		flags := make(common.VerifyStatusFlags)
		sum := float64(100.0)

		for _, sm := range v {
			sum = sum - sm.availability

			for k, v := range sm.flags {
				if v {
					flags[k] = v
				}
			}
		}

		avg := sum / float64(len(v))

		rs = append(rs, CatchpointSummary{
			Country: k,
			Avg:     avg,
			Flags:   flags,
		})
	}

	// Record result in metrics one time for each unique country
	if c.metrics != nil {
		domain := common.ExtractDomain(oe.URI)
		c.logger.Debug("Catchpoint verifier. processInstantTestResultSummary. Recording metrics for %d unique countries", len(m))
		for k := range m {
			normalizedCountry := common.NormalizeCountryForMetrics(k)

			// Calculate average probability for country
			v := m[k]
			sum := float64(100.0)
			for _, sm := range v {
				sum = sum - sm.availability
			}
			avg := sum / float64(len(v))

			c.logger.Debug("Catchpoint verifier. processInstantTestResultSummary. Recording result for country %s with %d nodes, avg probability %f", k, len(v), avg)
			c.metrics.RecordTestResult(c.Name(), domain, normalizedCountry, avg, 0)
		}
	}
	return &rs, nil
}

func (c *Catchpoint) Verify(or *common.ObserveResult) (*common.VerifyResult, error) {

	if or.Endpoints.IsEmpty() {
		return nil, errors.New("Catchpoint verifier cannot process empty endpoints")
	}

	c.logger.Debug("Catchpoint verifier is processing...")
	t1 := time.Now()

	token := c.options.CatchpointOptions.APIToken

	g := &errgroup.Group{}
	m := &sync.Map{}

	for _, oe := range or.Endpoints.Items() {

		g.Go(func() error {

			uri := common.NormalizeURI(oe.URI)
			var rr *[]vendors.CatchpointInstantTestResultReponse
			var err error

			countries := slices.Collect(maps.Keys(oe.Countries))
			if len(countries) == 0 {
				return nil
			}
			scheme := common.URIScheme(uri)

			c.logger.Debug("Catchpoint verifier is checking %s endpoint %s in countries %s", scheme, uri, countries)
			t1 := time.Now()

			switch scheme {
			case common.URISchemeHttp, common.URISchemeHttps:

				rr, err = c.verifyHttp(oe, token, scheme, countries)
				if err != nil {
					// Record error in metrics
					if c.metrics != nil {
						domain := common.ExtractDomain(oe.URI)
						for _, country := range countries {
							normalizedCountry := common.NormalizeCountryForMetrics(country)
							c.metrics.RecordTestError(c.Name(), domain, normalizedCountry, "verify_http_error", 0)
						}
					}
				}
			default:
				return fmt.Errorf("Catchpoint verifier has no support for %s endpoint %s in countries %s", scheme, uri, countries)
			}

			c.logger.Debug("Catchpoint verifier checked %s endpoint %s in %s in %s", scheme, uri, countries, time.Since(t1))

			if err != nil {
				return fmt.Errorf("Catchpoint verifier has error: %s", err)
			}

			if rr == nil {
				return nil
			}

			ve := &common.VerifyEndpoint{
				URI:       uri,
				Countries: common.VerifyCountries{},
			}

			rs, err := c.processInstantTestResultSummary(oe, rr)
			if err != nil {
				return err
			}
			for _, r := range *rs {

				vs := ve.Countries[r.Country]
				if vs == nil {
					vs = &common.VerifyStatus{}
				}
				vs.Probability = &r.Avg
				vs.Flags = r.Flags
				ve.Countries[r.Country] = vs
			}
			m.Store(nil, ve)
			return nil
		})
	}
	err := g.Wait()
	if err != nil {
		return nil, err
	}

	c.logger.Debug("Catchpoint verifier spent %s", time.Since(t1))

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

func NewCatchpoint(options *CatchpointOptions, observability *common.Observability) *Catchpoint {

	logger := observability.Logs()

	if utils.IsEmpty(options.CatchpointOptions.APIToken) {
		logger.Debug("Catchpoint verifier token is not defined. Skipped.")
		return nil
	}

	return &Catchpoint{
		options: options,
		logger:  logger,
		client:  vendors.NewCatchpoint(options.CatchpointOptions, observability),
		metrics: common.NewVerifierMetrics(observability.Metrics()),
	}
}
