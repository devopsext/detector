package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"golang.org/x/sync/errgroup"
)

type SimpleOptions struct {
	Name                   string
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
		err := fmt.Errorf("Simple %s detector has no sources", a.options.Name)
		return nil, err
	}

	g := &errgroup.Group{}
	m := &sync.Map{}

	for _, s := range items {

		g.Go(func() error {

			sr, err := s.Load()
			if err != nil {
				return err
			}

			r := &common.SourceResult{}

			for _, e := range sr.Endpoints.Items() {

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
				r.Endpoints.Add(e1)
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

func (a *Simple) observe(sr *common.SourceResult) ([]*common.ObserveResult, error) {

	items := a.options.ObserverConfigurations
	if len(items) == 0 {
		err := fmt.Errorf("Simple %s detector has no observer configurations", a.options.Name)
		return nil, err
	}

	g := &errgroup.Group{}
	m := &sync.Map{}

	for _, oc := range items {

		g.Go(func() error {

			old, err := oc.Observer.Observe(sr)
			if err != nil {
				return err
			}

			es := common.ObserveEndpoints{}

			for _, e := range old.Endpoints.Items() {

				if e == nil {
					continue
				}

				countries := make(common.ObserveCountries)
				for k, p := range e.Countries {

					if p == nil {
						continue
					}

					if *p < oc.Probability {
						continue
					}
					countries[k] = p
				}

				if len(countries) == 0 {
					continue
				}
				esp := es.Clone(e)
				esp.Countries = countries
				es.Add(esp)
			}

			if es.IsEmpty() {
				return nil
			}

			new := &common.ObserveResult{
				Endpoints: es,
			}
			m.Store(nil, new)
			return nil
		})
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

func (a *Simple) verify(or *common.ObserveResult) ([]*common.VerifyResult, error) {

	items := a.options.VerifierConfigurations
	if len(items) == 0 {
		err := fmt.Errorf("Simple %s detector has no verifier configurations", a.options.Name)
		return nil, err
	}

	g := &errgroup.Group{}
	m := &sync.Map{}

	for _, vc := range items {

		g.Go(func() error {

			old, err := vc.Verifier.Verify(or)
			if err != nil {
				return err
			}

			es := common.VerifyEndpoints{}

			for _, e := range old.Endpoints.Items() {

				if e == nil {
					continue
				}

				countries := make(common.VerifyCountries)
				for k, s := range e.Countries {

					p := s.Probability
					if p == nil {
						continue
					}

					if *p < vc.Probability {
						continue
					}
					countries[k] = s
				}

				if len(countries) == 0 {
					continue
				}
				en := es.Clone(e)
				en.Countries = countries
				es.Add(en)
			}

			if es.IsEmpty() {
				return nil
			}

			new := &common.VerifyResult{
				Endpoints: es,
			}
			m.Store(nil, new)
			return nil
		})
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

func (a *Simple) notify(vr *common.VerifyResult) error {

	items := a.options.NotifierConfigurations
	if len(items) == 0 {
		err := fmt.Errorf("Simple %s detector has no notifier configurations", a.options.Name)
		return err
	}

	g := &errgroup.Group{}

	for _, nc := range items {

		es := &common.VerifyEndpoints{}

		for _, e := range vr.Endpoints.Items() {

			if e == nil {
				continue
			}

			countries := make(common.VerifyCountries)
			for k, s := range e.Countries {

				p := s.Probability
				if p == nil {
					continue
				}

				if *p < nc.Probability {
					continue
				}
				countries[k] = s
			}

			if len(countries) == 0 {
				continue
			}
			en := es.Clone(e)
			en.Countries = countries
			es.Add(en)
		}

		if es.IsEmpty() {
			continue
		}

		g.Go(func() error {

			vrn := &common.VerifyResult{
				Endpoints: *es,
			}

			err := nc.Notifier.Notify(vrn)
			if err != nil {
				return err
			}
			return nil
		})
	}
	return g.Wait()
}

func (a *Simple) mergeSourceResults(srs []*common.SourceResult) *common.SourceResult {

	eps := common.SourceEndpoints{}

	for _, sr := range srs {

		if sr == nil {
			continue
		}
		eps.Merge(&sr.Endpoints)
	}

	if eps.IsEmpty() {
		return nil
	}
	return &common.SourceResult{
		Endpoints: eps,
	}
}

func (a *Simple) mergeObserveResults(ors []*common.ObserveResult) *common.ObserveResult {

	eps := common.ObserveEndpoints{}

	for _, sr := range ors {

		if sr == nil {
			continue
		}
		eps.Merge(&sr.Endpoints)
	}

	if eps.IsEmpty() {
		return nil
	}

	return &common.ObserveResult{
		Endpoints: eps,
	}
}

func (a *Simple) mergeVerifyResults(ors []*common.VerifyResult) *common.VerifyResult {

	eps := common.VerifyEndpoints{}

	for _, sr := range ors {

		if sr == nil {
			continue
		}
		eps.Merge(&sr.Endpoints)
	}

	if eps.IsEmpty() {
		return nil
	}
	return &common.VerifyResult{
		Endpoints: eps,
	}
}

func (a *Simple) Detect() error {

	if !a.lock.TryLock() {
		return fmt.Errorf("Simple %s detector already in a loop", a.options.Name)
	}
	defer a.lock.Unlock()

	a.logger.Debug("Simple %s detector is loading...", a.options.Name)
	t1 := time.Now()

	srs, err := a.load()
	if err != nil {
		a.logger.Debug("Simple %s detector cannot load from sources, error: %s", a.options.Name, err)
	}
	a.logger.Debug("Simple %s detector sources were loaded in %s", a.options.Name, time.Since(t1))

	sr := a.mergeSourceResults(srs)
	if sr == nil {
		a.logger.Debug("Simple %s detector has no source results", a.options.Name)
		return nil
	}

	a.logger.Debug("Simple %s detector is observing...", a.options.Name)
	t2 := time.Now()

	ors, err := a.observe(sr)
	if err != nil {
		a.logger.Error("Simple %s detector cannot observe, error: %s", a.options.Name, err)
	}
	a.logger.Debug("Simple %s detector observed in %s", a.options.Name, time.Since(t2))

	or := a.mergeObserveResults(ors)
	if or == nil {
		a.logger.Debug("Simple %s detector has no observe results", a.options.Name)
		return nil
	}

	a.logger.Debug("Simple %s detector is verifying...", a.options.Name)
	t3 := time.Now()

	vrs, err := a.verify(or)
	if err != nil {
		a.logger.Error("Simple %s detector cannot verify, error: %s", a.options.Name, err)
	}
	a.logger.Debug("Simple %s detector verified in %s", a.options.Name, time.Since(t3))

	vr := a.mergeVerifyResults(vrs)
	if vr == nil {
		a.logger.Debug("Simple %s detector has no verify results", a.options.Name)
		return nil
	}

	a.logger.Debug("Simple %s detector is notifying...", a.options.Name)
	t4 := time.Now()

	err = a.notify(vr)
	if err != nil {
		a.logger.Error("Simple %s detector cannot notify, error: %s", a.options.Name, err)
	}

	a.logger.Debug("Simple %s detector notified in %s", a.options.Name, time.Since(t4))

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
