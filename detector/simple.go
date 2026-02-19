package detector

import (
	"context"
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
	Countries              []string
	Triggers               *common.Triggers
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

	name := a.options.Name
	if utils.IsEmpty(name) {
		name = SimpleDetectorName
	}
	return name
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

			if sr == nil {
				return nil
			}

			r := &common.SourceResult{}

			for _, entry := range sr.Items.Items() {

				ep, ok := entry.(*common.SourceItem)
				if !ok {
					continue
				}

				if ep.Disabled {
					continue
				}

				name := a.Name()
				if !utils.Contains(ep.Detectors, name) && len(ep.Detectors) > 0 {
					continue
				}

				// filter countries to intersection with detector's countries
				if len(a.options.Countries) > 0 {
					nc := []string{}
					for _, c := range a.options.Countries {
						if utils.Contains(ep.Countries, c) {
							nc = append(nc, c)
						}
					}
					ep.Countries = nc
				}

				r.Items.Add(ep)
			}
			m.Store(s.Name(), r)
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

			or, err := oc.Observer.Observe(sr)
			if err != nil {
				return err
			}

			if or == nil {
				return nil
			}

			l := len(or.Items.Items())
			if l == 0 {
				return nil
			}

			or.Configuration = oc
			m.Store(oc.Observer.Name(), or)
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

			vr, err := vc.Verifier.Verify(or)
			if err != nil {
				return err
			}

			if vr == nil {
				return nil
			}

			l := len(or.Items.Items())
			if l == 0 {
				return nil
			}

			vr.Configuration = vc
			m.Store(vc.Verifier.Name(), vr)
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

func (a *Simple) TriggerKey(n common.Notifier, ep *common.VerifyItem) string {

	return fmt.Sprintf("%s: %s", n.Name(), ep.EntryIdent())
}

func (a *Simple) FilterTriggers(n common.Notifier, vr *common.VerifyItems) *common.VerifyItems {

	trs := a.options.Triggers
	if trs == nil {
		return vr
	}

	eps := &common.VerifyItems{}
	for _, entry := range vr.Items() {

		if entry == nil {
			continue
		}

		ve, ok := entry.(*common.VerifyItem)
		if !ok {
			continue
		}

		key := a.TriggerKey(n, ve)
		if !trs.Exists(key) {
			eps.Add(ve)
		}
	}

	if eps.IsEmpty() {
		return nil
	}
	return eps
}

func (a *Simple) UpdateTriggers(n common.Notifier, es *common.VerifyItems) {

	trs := a.options.Triggers
	if trs == nil {
		return
	}

	for _, entry := range es.Items() {

		if entry == nil {
			continue
		}

		ve, ok := entry.(*common.VerifyItem)
		if !ok {
			continue
		}

		key := a.TriggerKey(n, ve)
		if !trs.Exists(key) {
			trs.Update(key, ve)
		}
	}
}

func (a *Simple) notify(vr *common.VerifyResult) error {

	items := a.options.NotifierConfigurations
	if len(items) == 0 {
		err := fmt.Errorf("Simple %s detector has no notifier configurations", a.options.Name)
		return err
	}

	g := &errgroup.Group{}

	for _, nc := range items {

		es := &common.VerifyItems{}

		for _, entry := range vr.Items.Items() {

			if entry == nil {
				continue
			}

			ve, ok := entry.(*common.VerifyItem)
			if !ok {
				continue
			}

			countries := make(common.VerifyCountries)
			for k, s := range ve.EntryVerifyCountries() {

				if s == nil {
					continue
				}
				p := s.Probability
				if p == nil {
					a.logger.Debug("Skipping items for notify %s %s. Probability is nil", ve.EntryKey(), k)
					continue
				}

				if *p < nc.Probability {
					a.logger.Debug("Skipping items for notify %s %s %f %f. Probability is less than notifier probability", ve.EntryKey(), k, *p, nc.Probability)
					continue
				}
				countries[k] = s
			}

			if len(countries) == 0 {
				continue
			}
			en := es.Clone(ve)
			en.Countries = countries
			es.Add(en)
		}

		if es.IsEmpty() {
			continue
		}

		g.Go(func() error {

			nes := a.FilterTriggers(nc.Notifier, es)
			if nes == nil || len(nes.Items()) == 0 {
				return nil
			}

			vrn := &common.VerifyResult{
				Items: *nes,
			}

			err := nc.Notifier.Notify(vrn)
			if err != nil {
				return err
			}
			a.UpdateTriggers(nc.Notifier, nes)
			return nil
		})
	}
	return g.Wait()
}

func (a *Simple) mergeSourceResults(srs []*common.SourceResult) *common.SourceResult {

	eps := common.SourceItems{}

	for _, sr := range srs {

		if sr == nil {
			continue
		}
		eps.Add(sr.Items.Items()...)
	}

	r := eps.Reduce()

	if r.IsEmpty() {
		return nil
	}

	return &common.SourceResult{
		Items: r,
	}
}

func (a *Simple) mergeObserveResults(ors []*common.ObserveResult) *common.ObserveResult {

	eps := common.ObserveItems{}

	for _, sr := range ors {

		if sr == nil {
			continue
		}

		if sr.Configuration == nil {
			continue
		}

		es := &common.ObserveItems{}
		for _, entry := range sr.Items.Items() {

			if entry == nil {
				continue
			}

			oi, ok := entry.(*common.ObserveItem)
			if !ok {
				continue
			}

			countries := make(common.ObserveCountries)
			for k, p := range oi.EntryObserveCountries() {

				if p == nil {
					continue
				}

				if *p < sr.Configuration.Probability {
					continue
				}
				countries[k] = p
			}

			if len(countries) == 0 {
				continue
			}
			esp := es.Clone(oi)
			esp.Countries = countries
			es.Add(esp)
		}

		if es.IsEmpty() {
			continue
		}

		eps.Add(es.Items()...)
	}

	r := eps.Reduce()

	if r.IsEmpty() {
		return nil
	}

	return &common.ObserveResult{
		Items: r,
	}
}

func (a *Simple) mergeVerifyResults(vrs []*common.VerifyResult) *common.VerifyResult {

	vps := common.VerifyItems{}

	for _, vr := range vrs {

		if vr == nil {
			continue
		}

		if vr.Configuration == nil {
			continue
		}

		es := &common.VerifyItems{}
		for _, entry := range vr.Items.Items() {

			if entry == nil {
				continue
			}

			ve, ok := entry.(*common.VerifyItem)
			if !ok {
				continue
			}

			countries := make(common.VerifyCountries)
			for k, s := range ve.EntryVerifyCountries() {

				if s == nil {
					continue
				}

				p := s.Probability
				if p == nil {
					continue
				}

				if *p < vr.Configuration.Probability {
					continue
				}
				countries[k] = s
			}

			if len(countries) == 0 {
				continue
			}
			esp := es.Clone(ve)
			esp.Countries = countries
			es.Add(esp)
		}

		if es.IsEmpty() {
			continue
		}

		vps.Add(es.Items()...)
	}

	r := vps.Reduce()

	if r.IsEmpty() {
		return nil
	}

	return &common.VerifyResult{
		Items: r,
	}
}

func (a *Simple) Start(ctx context.Context) {

	for _, s := range a.options.Sources {
		err := s.Start(ctx)
		if err != nil {
			a.logger.Error("Simple %s detector has error: %s", a.Name(), err)
		}
	}
}

func (a *Simple) tryLoad() (*common.SourceResult, error) {

	a.logger.Debug("Simple %s detector is loading...", a.options.Name)
	t1 := time.Now()

	srs, err := a.load()
	if err != nil {
		a.logger.Debug("Simple %s detector cannot load from sources, error: %s", a.options.Name, err)
		return nil, err
	}
	a.logger.Debug("Simple %s detector sources were loaded in %s", a.options.Name, time.Since(t1))

	sr := a.mergeSourceResults(srs)
	if sr == nil {
		return nil, nil
	}

	for _, entry := range sr.Items.Items() {
		if entry == nil {
			continue
		}
		a.logger.Debug("Simple %s detector source item %s %s", a.options.Name, entry.EntryKey(), entry.EntryCountries())
	}
	return sr, nil
}

func (a *Simple) tryObserve(sr *common.SourceResult) (*common.ObserveResult, error) {

	a.logger.Debug("Simple %s detector is observing...", a.options.Name)
	t2 := time.Now()

	ors, err := a.observe(sr)
	if err != nil {
		a.logger.Error("Simple %s detector cannot observe, error: %s", a.options.Name, err)
		return nil, err
	}
	a.logger.Debug("Simple %s detector observed in %s", a.options.Name, time.Since(t2))

	or := a.mergeObserveResults(ors)
	if or == nil {
		return nil, nil
	}

	for _, entry := range or.Items.Items() {
		if entry == nil {
			continue
		}
		arr := []string{}
		for k, v := range entry.EntryObserveCountries() {
			if v != nil {
				arr = append(arr, fmt.Sprintf("%s=%0.2f", k, *v))
			}
		}
		a.logger.Debug("Simple %s detector observed item %s %s", a.options.Name, entry.EntryKey(), arr)
	}
	return or, nil
}

func (a *Simple) tryVerify(or *common.ObserveResult) (*common.VerifyResult, error) {

	a.logger.Debug("Simple %s detector is verifying...", a.options.Name)
	t3 := time.Now()

	vrs, err := a.verify(or)
	if err != nil {
		a.logger.Error("Simple %s detector cannot verify, error: %s", a.options.Name, err)
		return nil, err
	}
	a.logger.Debug("Simple %s detector verified in %s", a.options.Name, time.Since(t3))

	vr := a.mergeVerifyResults(vrs)
	if vr == nil {
		return nil, nil
	}

	for _, entry := range vr.Items.Items() {
		if entry == nil {
			continue
		}
		arr := []string{}
		for k, s := range entry.EntryVerifyCountries() {
			if s == nil {
				continue
			}
			flags := []string{}
			for f, b := range s.Flags {
				if b {
					flags = append(flags, f)
				}
			}
			sflags := ""
			if len(flags) > 0 {
				sflags = fmt.Sprintf(":%s", flags)
			}
			if s.Probability != nil {
				arr = append(arr, fmt.Sprintf("%s=%0.2f%s", k, *s.Probability, sflags))
			}
		}
		a.logger.Debug("Simple %s detector verified item %s %s", a.options.Name, entry.EntryKey(), arr)
	}
	return vr, nil
}

func (a *Simple) tryNotify(vr *common.VerifyResult) error {

	a.logger.Debug("Simple %s detector is notifying...", a.options.Name)
	t4 := time.Now()

	err := a.notify(vr)
	if err != nil {
		a.logger.Error("Simple %s detector cannot notify, error: %s", a.options.Name, err)
		return err
	}
	a.logger.Debug("Simple %s detector notified in %s", a.options.Name, time.Since(t4))
	return nil
}

func (a *Simple) Detect() error {

	if !a.lock.TryLock() {
		return fmt.Errorf("Simple %s detector already in a loop", a.options.Name)
	}
	defer a.lock.Unlock()

	sr, _ := a.tryLoad()
	if sr == nil {
		a.logger.Debug("Simple %s detector has no source results", a.options.Name)
		return nil
	}

	or, _ := a.tryObserve(sr)
	if or == nil {
		a.logger.Debug("Simple %s detector has no observe results", a.options.Name)
		return nil
	}

	vr, _ := a.tryVerify(or)
	if vr == nil {
		a.logger.Debug("Simple %s detector has no verify results", a.options.Name)
		return nil
	}

	err := a.tryNotify(vr)
	if err != nil {
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
