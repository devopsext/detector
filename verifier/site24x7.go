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
	"strings"
	"sync"
	"time"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	tools "github.com/devopsext/tools/common"
	vendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
	"github.com/jinzhu/copier"
	"golang.org/x/sync/errgroup"
)

type Site24x7Options struct {
	vendors.Site24x7Options
	MonitorName           string
	MonitorFrequency      string
	MonitorTimeout        int
	HttpMethod            string
	HttpUserAgent         string
	NotificationProfileID string
	ThresholdProfileID    string
	UserGroupIDs          []string
	PollTimeout           int
	PollDelay             int
	LogReportFile         string
}

type Site24x7Summary struct {
	Country string
	Avg     float64
	Flags   map[common.VerifyStatusFlag]bool
}

type Site24x7 struct {
	logger  sreCommon.Logger
	options *Site24x7Options
	client  *vendors.Site24x7
}

const Site24x7VerifierName = "Site24x7"

func (s *Site24x7) Name() string {
	return Site24x7VerifierName
}

func (s *Site24x7) cloneSite24x7Options(opts vendors.Site24x7Options, token string) vendors.Site24x7Options {

	r := vendors.Site24x7Options{}
	copier.Copy(&r, &opts)
	r.AccessToken = token
	return r
}

func (s *Site24x7) createWebsiteMonitor(token, name, url string, countries []string) (*vendors.Site24x7WebsiteMonitorResponse, error) {

	opts := s.cloneSite24x7Options(s.options.Site24x7Options, token)
	createOpts := vendors.Site24x7WebsiteMonitorOptions{
		Name:                  name,
		URL:                   url,
		Method:                s.options.HttpMethod,
		Timeout:               s.options.MonitorTimeout,
		Frequency:             s.options.MonitorFrequency,
		Countries:             countries,
		UserAgent:             s.options.HttpUserAgent,
		NotificationProfileID: s.options.NotificationProfileID,
		ThresholdProfileID:    s.options.ThresholdProfileID,
		UserGroupIDs:          s.options.UserGroupIDs,
	}

	d, err := s.client.CustomCreateWebsiteMonitor(opts, createOpts)
	if err != nil {
		return nil, s.client.CheckError(d, err)
	}

	r := vendors.Site24x7WebsiteMonitorResponse{}
	err = json.Unmarshal(d, &r)
	if err != nil {
		return nil, err
	}

	err = s.client.CheckResponse(r.Site24x7Reponse)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Site24x7) deleteLocationProfile(token, ID string) (*vendors.Site24x7DeleteResponse, error) {

	opts := s.cloneSite24x7Options(s.options.Site24x7Options, token)
	deleteOpts := vendors.Site24x7LocationProfileOptions{
		ID: ID,
	}

	d, err := s.client.CustomDeleteLocationProfile(opts, deleteOpts)
	if err != nil {
		return nil, s.client.CheckError(d, err)
	}

	r := vendors.Site24x7DeleteResponse{}
	err = json.Unmarshal(d, &r)
	if err != nil {
		return nil, err
	}

	err = s.client.CheckResponse(r.Site24x7Reponse)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Site24x7) deleteMonitor(token, ID string) (*vendors.Site24x7DeleteResponse, error) {

	opts := s.cloneSite24x7Options(s.options.Site24x7Options, token)
	monitorOpts := vendors.Site24x7MonitorOptions{
		ID: ID,
	}

	d, err := s.client.CustomDeleteMonitor(opts, monitorOpts)
	if err != nil {
		return nil, s.client.CheckError(d, err)
	}

	r := vendors.Site24x7DeleteResponse{}
	err = json.Unmarshal(d, &r)
	if err != nil {
		return nil, err
	}

	err = s.client.CheckResponse(r.Site24x7Reponse)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Site24x7) pollNow(token, ID string) (*vendors.Site24x7PollStatusReponse, error) {

	opts := s.cloneSite24x7Options(s.options.Site24x7Options, token)
	monitorOpts := vendors.Site24x7MonitorOptions{
		ID: ID,
	}

	d, err := s.client.CustomPollMonitor(opts, monitorOpts)
	if err != nil {
		return nil, s.client.CheckError(d, err)
	}

	r := vendors.Site24x7PollStatusReponse{}
	err = json.Unmarshal(d, &r)
	if err != nil {
		return nil, err
	}

	err = s.client.CheckResponse(r.Site24x7Reponse)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Site24x7) waitPollSuccessOrCancel(ctx context.Context, token, ID, name string) bool {

	opts := s.cloneSite24x7Options(s.options.Site24x7Options, token)
	monitorOpts := vendors.Site24x7MonitorOptions{
		ID: ID,
	}

	t := time.Duration(s.options.PollDelay) * time.Second
	for {

		select {
		case <-ctx.Done():
			return false
		case <-time.After(t):

			d, err := s.client.CustomGetPollingStatus(opts, monitorOpts)
			if err != nil {
				continue
			}

			r := vendors.Site24x7PollStatusReponse{}
			err = json.Unmarshal(d, &r)
			if err != nil {
				continue
			}

			err = s.client.CheckResponse(r.Site24x7Reponse)
			if err != nil {
				continue
			}

			s.logger.Debug("Site24x7 verifier polling status %s for monitor %s", r.Data.Status, name)

			if strings.ToLower(r.Data.Status) == "completed" {
				return true
			}
		}
	}
}

func (s *Site24x7) getLogReport(token, ID string) (*vendors.Site24x7LogReportReponse, error) {

	start := time.Now().Format("2006-01-02")
	end := ""

	opts := s.cloneSite24x7Options(s.options.Site24x7Options, token)

	reportOpts := vendors.Site24x7LogReportOptions{
		Site24x7MonitorOptions: vendors.Site24x7MonitorOptions{
			ID: ID,
		},
		StartDate: start,
		EndDate:   end,
	}

	d, err := s.client.CustomGetLogReport(opts, reportOpts)
	if err != nil {
		return nil, s.client.CheckError(d, err)
	}

	r := vendors.Site24x7LogReportReponse{}
	err = json.Unmarshal(d, &r)
	if err != nil {
		return nil, err
	}

	err = s.client.CheckResponse(r.Site24x7Reponse)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Site24x7) verifyHttp(oe *common.ObserveEndpoint, token, scheme string, countries []string) (*vendors.Site24x7LogReportData, error) {

	u, err := url.Parse(oe.URI)
	if err != nil {
		return nil, err
	}

	murl := oe.URI
	if utils.IsEmpty(u.Scheme) {
		murl = fmt.Sprintf("%s://%s", scheme, murl)
	}

	suffix := fmt.Sprintf("%s [%s] %s", s.options.MonitorName, strings.Join(countries, ","), murl)
	name := fmt.Sprintf("%s %s", s.options.MonitorName, common.Md5ToString([]byte(suffix)))

	s.logger.Debug("Site24x7 verifier is creating monitor %s for endpoint %s in countries %s...", name, oe.URI, countries)
	wmr, err := s.createWebsiteMonitor(token, name, murl, countries)
	if err != nil {
		return nil, err
	}

	s.logger.Debug("Site24x7 verifier is polling now monitor %s...", wmr.Data.DisplayName)
	_, err = s.pollNow(token, wmr.Data.MonitorID)
	if err != nil {
		return nil, err
	}

	var cancel context.CancelFunc
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.options.PollTimeout)*time.Second)
	defer cancel()

	var lrr *vendors.Site24x7LogReportReponse
	var lerr error

	s.logger.Debug("Site24x7 verifier is waiting poll for monitor %s...", wmr.Data.DisplayName)
	s.waitPollSuccessOrCancel(ctx, token, wmr.Data.MonitorID, name)

	s.logger.Debug("Site24x7 verifier is getting log report for monitor %s...", wmr.Data.DisplayName)
	lr, err := s.getLogReport(token, wmr.Data.MonitorID)
	if err != nil {
		lerr = err
	} else {
		lrr = lr
	}

	s.logger.Debug("Site24x7 verifier is deleting monitor %s...", wmr.Data.DisplayName)
	_, err = s.deleteMonitor(token, wmr.Data.MonitorID)
	if err == nil {
		s.deleteLocationProfile(token, wmr.Data.LocationProfileID)
	}

	if lerr != nil {
		return nil, lerr
	}

	if lrr == nil || lrr.Data == nil {
		return nil, nil
	}

	return lrr.Data, nil
}

func (s *Site24x7) loadLogReport(file string) (*vendors.Site24x7LogReportData, error) {

	data, err := utils.Content(file)
	if err != nil {
		return nil, err
	}

	var lrr vendors.Site24x7LogReportReponse
	err = json.Unmarshal(data, &lrr)
	if err != nil {
		return nil, err
	}

	if lrr.Data == nil {
		return nil, nil
	}
	return lrr.Data, nil
}

func (s *Site24x7) getLocationTemplate(token string) (*vendors.Site24x7LocationTemplateReponse, error) {

	opts := s.cloneSite24x7Options(s.options.Site24x7Options, token)

	d, err := s.client.CustomGetLocationTemplate(opts)
	if err != nil {
		return nil, s.client.CheckError(d, err)
	}

	ltr := vendors.Site24x7LocationTemplateReponse{}
	err = json.Unmarshal(d, &ltr)
	if err != nil {
		return nil, err
	}

	err = s.client.CheckResponse(ltr.Site24x7Reponse)
	if err != nil {
		return nil, err
	}
	return &ltr, nil
}

func (s *Site24x7) findCountryByLocation(ltd *vendors.Site24x7LocationTemplateData, locationID string) string {

	if ltd == nil {
		return ""
	}
	for _, l := range ltd.Locations {

		if l.LocationID != locationID {
			continue
		}

		short := tools.CountryShort(l.CountryName)
		if !utils.IsEmpty(short) {
			return short
		}
	}
	return ""
}

func (s *Site24x7) processLogReportSummary(oe *common.ObserveEndpoint, locations *vendors.Site24x7LocationTemplateReponse,
	report []*vendors.Site24x7LogReportDataReport, collectionTypes []string) []*Site24x7Summary {

	r := []*Site24x7Summary{}

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

	for _, dr := range report {

		if !utils.Contains(collectionTypes, dr.DataCollectionType) {
			continue
		}

		country := s.findCountryByLocation(locations.Data, dr.LocationID)
		if utils.IsEmpty(country) {
			continue
		}
		country = common.NormalizeCountry(country)

		sm := m[country]
		if sm == nil {
			sm = []summary{}
		}

		availability := float64(0.0)
		if dr.Availability == "1" {
			availability = float64(100.0)
		}

		flags := make(common.VerifyStatusFlags)

		if len(oe.IPs) > 0 {
			exists := false
			for _, v := range reIPs {
				if v.MatchString(dr.ResolvedIP) {
					exists = true
					break
				}
			}
			flags[common.VerifyStatusFlagWrongIPAddress] = !exists
		}

		if reCode != nil {
			if !reCode.MatchString(dr.ResponseCode) {
				flags[common.VerifyStatusFlagWrongResponseCode] = true
			}
		}

		sm = append(sm, summary{
			availability: availability,
			flags:        flags,
		})
		m[country] = sm
	}

	for k, v := range m {

		flags := make(common.VerifyStatusFlags)
		sum := float64(0.0)

		for _, sm := range v {
			sum = sum + sm.availability

			for k, v := range sm.flags {
				if v {
					flags[k] = v
				}
			}
		}

		avg := sum / float64(len(v))

		r = append(r, &Site24x7Summary{
			Country: k,
			Avg:     avg,
			Flags:   flags,
		})
	}
	return r
}

func (s *Site24x7) Verify(or *common.ObserveResult) (*common.VerifyResult, error) {

	if or.Endpoints.IsEmpty() {
		return nil, errors.New("Site24x7 verifier cannot process empty endpoints")
	}

	s.logger.Debug("Site24x7 verifier is processing...")
	t1 := time.Now()

	token, err := s.client.CustomGetAccessToken(s.options.Site24x7Options)
	if err != nil {
		return nil, err
	}

	s.logger.Debug("Site24x7 verifier is getting location templates...")

	locations, err := s.getLocationTemplate(token)
	if err != nil {
		return nil, err
	}

	g := &errgroup.Group{}
	m := &sync.Map{}

	for _, oe := range or.Endpoints.Items() {

		g.Go(func() error {

			uri := common.NormalizeURI(oe.URI)
			var rd *vendors.Site24x7LogReportData
			var err error

			if utils.FileExists(s.options.LogReportFile) {

				rd, err = s.loadLogReport(s.options.LogReportFile)

			} else {

				countries := slices.Collect(maps.Keys(oe.Countries))
				if len(countries) == 0 {
					return nil
				}
				scheme := common.URIScheme(uri)

				s.logger.Debug("Site24x7 verifier is checking %s endpoint %s in countries %s", scheme, uri, countries)
				t1 := time.Now()

				switch scheme {
				case common.URISchemeHttp, common.URISchemeHttps:

					rd, err = s.verifyHttp(oe, token, scheme, countries)
				default:
					return fmt.Errorf("Site24x7 verifier has no support for %s endpoint %s in countries %s", scheme, uri, countries)
				}

				s.logger.Debug("Site24x7 verifier checked %s endpoint %s in %s in %s", scheme, uri, countries, time.Since(t1))
			}

			if err != nil {
				return fmt.Errorf("Site24x7 verifier has error: %s", err)
			}

			if rd == nil {
				return nil
			}

			ve := &common.VerifyEndpoint{
				URI:       uri,
				Countries: common.VerifyCountries{},
			}

			collectionTypes := []string{vendors.Site24x7DataCollectionTypePollNow, vendors.Site24x7DataCollectionTypeNormal}
			rs := s.processLogReportSummary(oe, locations, rd.Report, collectionTypes)

			for _, r := range rs {

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
	err = g.Wait()
	if err != nil {
		return nil, err
	}

	s.logger.Debug("Site24x7 verifier spent %s", time.Since(t1))

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

func NewSite24x7(options *Site24x7Options, observability *common.Observability) *Site24x7 {

	logger := observability.Logs()

	if utils.IsEmpty(options.Site24x7Options.ClientID) || utils.IsEmpty(options.Site24x7Options.ClientSecret) {
		logger.Debug("Site24x7 verifier client ID or secret is not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.Site24x7Options.RefreshToken) {
		logger.Debug("Site24x7 verifier refresh token is not defined. Skipped.")
		return nil
	}

	return &Site24x7{
		options: options,
		logger:  logger,
		client:  vendors.NewSite24x7(options.Site24x7Options, observability),
	}
}
