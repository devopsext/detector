package observer

import (
	"errors"
	"math/rand/v2"
	"time"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
)

type RandomOptions struct {
	Min   float64
	Max   float64
	Delay int
}

type Random struct {
	options *RandomOptions
	logger  sreCommon.Logger
}

const ObserverRandomName = "Random"

func (rd *Random) Name() string {
	return ObserverRandomName
}

func (rd *Random) Observe(sr *common.SourceResult) (*common.ObserveResult, error) {

	if sr.Items.IsEmpty() {
		return nil, errors.New("Random observer cannot process empty items")
	}

	rd.logger.Debug("Random observer is processing...")
	t1 := time.Now()

	es := common.ObserveItems{}

	for _, entry := range sr.Items.Items() {

		if entry == nil {
			continue
		}

		key := entry.EntryKey()
		countries := make(common.ObserveCountries)

		for _, c := range entry.EntryCountries() {

			value := rd.options.Min + rand.Float64()*(rd.options.Max-rd.options.Min)
			country := common.NormalizeCountry(c)
			countries[country] = &value
		}

		if len(countries) == 0 {
			continue
		}

		time.Sleep(time.Duration(rd.options.Delay) * time.Millisecond)

		ep := &common.ObserveItem{
			Key:       key,
			Countries: countries,
		}
		// domain-specific fields
		if se, ok := entry.(*common.SourceItem); ok {
			ep.IPs = se.IPs
			ep.Response = se.Response
		}
		es.Add(ep)
	}

	rd.logger.Debug("Random observer spent %s", time.Since(t1))

	r := &common.ObserveResult{
		Items: es,
	}
	return r, nil
}

func NewRandom(options *RandomOptions, observability *common.Observability) *Random {

	logger := observability.Logs()

	return &Random{
		options: options,
		logger:  logger,
	}
}
