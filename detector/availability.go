package detector

import (
	"errors"
	"slices"
	"sync"

	"maps"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"golang.org/x/sync/errgroup"
)

type AvailabilityOptions struct {
	Schedule  string
	Sources   string
	Observers string
	Verifiers string
	Notifiers string
}

type Availability struct {
	options   *AvailabilityOptions
	logger    sreCommon.Logger
	sources   *common.Sources
	observers *common.Observers
	verifiers *common.Verifiers
	notifiers *common.Notifiers
	lock      *sync.Mutex
}

const AvailabilityDetectorName = "Availability"

// Availability

func (a *Availability) Name() string {
	return AvailabilityDetectorName
}

func (a *Availability) Schedule() string {
	return a.options.Schedule
}

func (a *Availability) load() ([]*common.SourceResult, error) {

	items := a.sources.Items()
	if len(items) == 0 {
		return nil, errors.New("Availability detector cannot find sources")
	}

	g := &errgroup.Group{}
	m := &sync.Map{}

	sources := a.sources.FindByPattern(a.options.Sources)
	if len(sources) == 0 {
		return nil, errors.New("Availability detector has no sources")
	}
	keys := slices.Collect(maps.Keys(sources))

	for _, s := range items {

		name := s.Name()
		if !utils.Contains(keys, name) {
			continue
		}

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
				r.Endpoints = append(r.Endpoints, e)
			}
			m.Store(name, r)
			return nil
		})
	}

	g.Wait()

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

func (a *Availability) observe(sr *common.SourceResult) ([]*common.ObserveResult, error) {

	items := a.observers.Items()
	if len(items) == 0 {
		return nil, errors.New("Availability detector cannot find observers")
	}

	g := &errgroup.Group{}
	m := &sync.Map{}

	observersConfig := a.observers.FindConfigurationByPattern(a.options.Observers)
	if len(observersConfig) == 0 {
		return nil, errors.New("Availability detector has no observers configurations")
	}
	keys := slices.Collect(maps.Keys(observersConfig))

	for _, o := range items {

		name := o.Name()
		if !utils.Contains(keys, name) {
			continue
		}

		g.Go(func() error {

			old, err := o.Observe(sr)
			if err != nil {
				return err
			}

			probability := float64(0.0)
			oc := observersConfig[name]
			if oc != nil {
				probability = oc.Probability
			}

			es := common.ObserveEndpoints{}

			for _, e := range old.Endpoints {

				if e == nil {
					continue
				}

				countries := make(common.ObserveCountries)
				for k, p := range e.Countries {

					if *p < probability {
						continue
					}
					countries[k] = p
				}

				if len(countries) == 0 {
					continue
				}
				es = append(es, &common.ObserveEndpoint{
					URI:       e.URI,
					Countries: countries,
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
			m.Store(o.Name(), new)
			return nil
		})
	}

	g.Wait()

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

func (a *Availability) Detect() error {

	if !a.lock.TryLock() {
		return errors.New("Availability detector already in a loop")
	}
	defer a.lock.Unlock()

	srs, err := a.load()
	if err != nil {
		a.logger.Debug("Availability detector cannot load from sources, error: %s", err)
		return err
	}

	for _, sr := range srs {

		a.logger.Debug("Availability detector source %s found %d endpoints", sr.Source.Name(), len(sr.Endpoints))

		_, err := a.observe(sr)
		if err != nil {
			return err
		}
	}

	//a.logger.Debug("Availability detector found %d endpoints", len(endpoints))

	return nil
}

func NewAvailability(options *AvailabilityOptions, observability *common.Observability,
	sources *common.Sources, observers *common.Observers, verifiers *common.Verifiers, notifiers *common.Notifiers) *Availability {

	logger := observability.Logs()

	if utils.IsEmpty(options.Sources) {
		logger.Debug("Availability detector has no sources. Skipped")
		return nil
	}

	if utils.IsEmpty(options.Observers) {
		logger.Debug("Availability detector has no observers. Skipped")
		return nil
	}

	if utils.IsEmpty(options.Verifiers) {
		logger.Debug("Availability detector has no verifiers. Skipped")
		return nil
	}

	if utils.IsEmpty(options.Notifiers) {
		logger.Debug("Availability detector has no notifiers. Skipped")
		return nil
	}

	return &Availability{
		options:   options,
		logger:    logger,
		sources:   sources,
		observers: observers,
		verifiers: verifiers,
		notifiers: notifiers,
		lock:      &sync.Mutex{},
	}
}
