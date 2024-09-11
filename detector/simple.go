package detector

import (
	"errors"
	"sync"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"golang.org/x/sync/errgroup"
)

type SimpleOptions struct {
	Schedule               string
	Sources                []common.Source
	ObserverConfigurations []*common.ObserverConfiguration
	VerifierConfigurations []*common.VerifierConfiguration
	NotifierConfigurations []*common.NotifierConfiguration
}

type Simple struct {
	options *SimpleOptions
	logger  sreCommon.Logger
	lock    *sync.Mutex
}

const SimpleDetectorName = "Simple"

// Simple

func (a *Simple) Name() string {
	return SimpleDetectorName
}

func (a *Simple) Schedule() string {
	return a.options.Schedule
}

func (a *Simple) load() ([]*common.SourceResult, error) {

	items := a.options.Sources
	if len(items) == 0 {
		return nil, errors.New("Simple detector has no sources")
	}

	g := &errgroup.Group{}
	m := &sync.Map{}

	for _, s := range items {

		g.Go(func() error {

			sr, err := s.Load()
			if err != nil {
				return err
			}

			r := &common.SourceResult{
				Source: s,
			}

			for _, e := range sr.Endpoints {

				if e.Disabled {
					continue
				}

				var e1 *common.SourceEndpoint
				if utils.Contains(e.Detectors, a.Name()) || len(e.Detectors) == 0 {
					e1 = e
				}

				if e1 == nil {
					continue
				}
				r.Endpoints = append(r.Endpoints, e1)
			}
			m.Store(nil, r)
			return nil
		})
	}

	err := g.Wait()
	if err != nil {
		return nil, err
	}

	r := []*common.SourceResult{}
	m.Range(func(key, value any) bool {

		e, ok := value.(*common.SourceResult)
		if !ok {
			return false
		}
		r = append(r, e)
		return true
	})
	return r, nil
}

func (a *Simple) observe(srs []*common.SourceResult) ([]*common.ObserveResult, error) {

	items := a.options.ObserverConfigurations
	if len(items) == 0 {
		return nil, errors.New("Simple detector has no observer configurations")
	}

	g := &errgroup.Group{}
	m := &sync.Map{}

	for _, oc := range items {

		for _, sr := range srs {

			g.Go(func() error {

				old, err := oc.Observer.Observe(sr)
				if err != nil {
					return err
				}

				es := common.ObserveEndpoints{}

				for _, e := range old.Endpoints {

					if e == nil {
						continue
					}

					countries := make(common.ObserveCountries)
					for k, p := range e.Countries {

						if *p < oc.Probability {
							continue
						}
						countries[k] = p
					}

					if len(countries) == 0 {
						continue
					}
					es = append(es, &common.ObserveEndpoint{
						URI:            e.URI,
						Countries:      countries,
						SourceEndpoint: e.SourceEndpoint,
					})
				}

				if len(es) == 0 {
					return nil
				}

				new := &common.ObserveResult{
					Observer:     old.Observer,
					SourceResult: old.SourceResult,
					Endpoints:    es,
				}
				m.Store(nil, new)
				return nil
			})
		}
	}

	err := g.Wait()
	if err != nil {
		return nil, err
	}

	r := []*common.ObserveResult{}
	m.Range(func(key, value any) bool {

		e, ok := value.(*common.ObserveResult)
		if !ok {
			return false
		}
		r = append(r, e)
		return true
	})
	return r, nil
}

func (a *Simple) verify(ors []*common.ObserveResult) ([]*common.VerifyResult, error) {

	items := a.options.VerifierConfigurations
	if len(items) == 0 {
		return nil, errors.New("Simple detector has no verifier configurations")
	}

	g := &errgroup.Group{}
	m := &sync.Map{}

	for _, vc := range items {

		for _, or := range ors {

			g.Go(func() error {

				old, err := vc.Verifier.Verify(or)
				if err != nil {
					return err
				}

				es := common.VerifyEndpoints{}

				for _, e := range old.Endpoints {

					if e == nil {
						continue
					}

					countries := make(common.VerifyCountries)
					for k, s := range e.Countries {

						p := s.Probability
						if *p < vc.Probability {
							continue
						}
						countries[k] = s
					}

					if len(countries) == 0 {
						continue
					}
					es = append(es, &common.VerifyEndpoint{
						URI:             e.URI,
						Countries:       countries,
						ObserveEndpoint: e.ObserveEndpoint,
					})
				}

				if len(es) == 0 {
					return nil
				}

				new := &common.VerifyResult{
					Verifier:      old.Verifier,
					ObserveResult: old.ObserveResult,
					Endpoints:     es,
				}
				m.Store(nil, new)
				return nil
			})
		}
	}

	err := g.Wait()
	if err != nil {
		return nil, err
	}

	r := []*common.VerifyResult{}
	m.Range(func(key, value any) bool {

		e, ok := value.(*common.VerifyResult)
		if !ok {
			return false
		}
		r = append(r, e)
		return true
	})
	return r, nil
}

func (a *Simple) notify(vrs []*common.VerifyResult) ([]*common.NotifyResult, error) {

	items := a.options.NotifierConfigurations
	if len(items) == 0 {
		return nil, errors.New("Simple detector has no notifier configurations")
	}

	g := &errgroup.Group{}
	m := &sync.Map{}

	for _, nc := range items {

		for _, vr := range vrs {

			g.Go(func() error {

				_, err := nc.Notifier.Notify(vr)
				if err != nil {
					return err
				}

				/*probability := float64(0.0)
				vc := verifiersConfig[name]
				if vc != nil {
					probability = vc.Probability
				}

				es := common.VerifyEndpoints{}

				for _, e := range old.Endpoints {

					if e == nil {
						continue
					}

					countries := make(common.VerifyCountries)
					for k, s := range e.Countries {

						p := s.Probability
						if *p < probability {
							continue
						}
						countries[k] = s
					}

					if len(countries) == 0 {
						continue
					}
					es = append(es, &common.VerifyEndpoint{
						URI:             e.URI,
						Countries:       countries,
						ObserveEndpoint: e.ObserveEndpoint,
					})
				}

				if len(es) == 0 {
					return nil
				}

				new := &common.NotifyResult{
					Notifier:     old.Notifier,
					VerifyResult: old.VerifyResult,
				}
				m.Store(nil, new)
				*/
				return nil
			})
		}
	}

	err := g.Wait()
	if err != nil {
		return nil, err
	}

	r := []*common.NotifyResult{}
	m.Range(func(key, value any) bool {

		e, ok := value.(*common.NotifyResult)
		if !ok {
			return false
		}
		r = append(r, e)
		return true
	})
	return r, nil
}

func (a *Simple) Detect() error {

	if !a.lock.TryLock() {
		return errors.New("Simple detector already in a loop")
	}
	defer a.lock.Unlock()

	srs, err := a.load()
	if err != nil {
		a.logger.Debug("Simple detector cannot load from sources, error: %s", err)
		return err
	}

	// merge is needed here
	/*for _, sr := range srs {
		if sr.Endpoints
	}*/

	ors, err := a.observe(srs)
	if err != nil {
		a.logger.Error("Simple detector cannot observe, error: %s", err)
		return err
	}

	// merge is needed here

	vrs, err := a.verify(ors)
	if err != nil {
		a.logger.Error("Simple detector cannot verify, error: %s", err)
		return err
	}

	// merge is needed here

	_, err = a.notify(vrs)
	if err != nil {
		a.logger.Error("Simple detector cannot notify, error: %s", err)
		return err
	}

	return nil
}

func NewSimple(options *SimpleOptions, observability *common.Observability) *Simple {

	logger := observability.Logs()

	if utils.IsEmpty(options.Sources) {
		logger.Debug("Simple detector has no sources. Skipped")
		return nil
	}

	return &Simple{
		options: options,
		logger:  logger,
		lock:    &sync.Mutex{},
	}
}
