package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	vendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
	"github.com/jinzhu/copier"
	"golang.org/x/sync/errgroup"
)

type Site24x7Options struct {
	vendors.Site24x7Options
	MonitorName           string
	HttpMethod            string
	HttpUserAgent         string
	NotificationProfileID string
	ThresholdProfileID    string
	UserGroupIDs          []string
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

func (s *Site24x7) createWebsiteMonitor(token, url string, countries []string) (*vendors.Site24x7WebsiteMonitorResponse, error) {

	opts := s.cloneSite24x7Options(s.options.Site24x7Options, token)
	createOpts := vendors.Site24x7WebsiteMonitorOptions{
		Name:                  s.options.MonitorName,
		URL:                   url,
		Method:                s.options.HttpMethod,
		Countries:             countries,
		UserAgent:             s.options.HttpUserAgent,
		NotificationProfileID: s.options.NotificationProfileID,
		ThresholdProfileID:    s.options.ThresholdProfileID,
		UserGroupIDs:          s.options.UserGroupIDs,
	}

	d, err := s.client.CustomCreateWebsiteMonitor(opts, createOpts)
	if err != nil {
		return nil, err
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

func (s *Site24x7) Verify(or *common.ObserveResult) (*common.VerifyResult, error) {

	if len(or.Endpoints) == 0 {
		return nil, errors.New("Site24x7 cannot process empty endpoints")
	}

	token, err := s.client.CustomGetAccessToken(s.options.Site24x7Options)
	if err != nil {
		return nil, err
	}

	g := &errgroup.Group{}

	for _, o := range or.Endpoints {

		g.Go(func() error {

			countries := slices.Collect(maps.Keys(o.Countries))
			scheme := common.URIScheme(o.URI)

			switch scheme {
			case common.URISchemeHttp, common.URISchemeHttps:

				_, err := s.createWebsiteMonitor(token, o.URI, countries)
				if err != nil {
					return err
				}

			default:
				return fmt.Errorf("Site24x7 has no support for endpoint: %s", o.URI)
			}
			return nil
		})
	}
	err = g.Wait()
	if err != nil {
		return nil, err
	}

	/*
		  - create new monitor for certain endpoints and countries, including location profile
			- initiate poll now check
			- wait until polling status will be success/error
			- get log report, check ip addresses and unvailability
			- delete location profile, and monitor
	*/

	vs := common.VerifyEndpoints{}

	r := &common.VerifyResult{
		Verifier:      s,
		ObserveResult: or,
		Endpoints:     vs,
	}
	return r, nil
}

func NewSite24x7(options *Site24x7Options, observability *common.Observability) *Site24x7 {

	logger := observability.Logs()

	if utils.IsEmpty(options.Site24x7Options.ClientID) || utils.IsEmpty(options.Site24x7Options.ClientSecret) {
		logger.Debug("Site24x7 client ID or secret is not defined. Skipped.")
		return nil
	}

	if utils.IsEmpty(options.Site24x7Options.RefreshToken) {
		logger.Debug("Site24x7 refresh token is not defined. Skipped.")
		return nil
	}

	return &Site24x7{
		options: options,
		logger:  logger,
		client:  vendors.NewSite24x7(options.Site24x7Options, observability),
	}
}
