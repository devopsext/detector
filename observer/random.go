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

	if sr.Endpoints.IsEmpty() {
		return nil, errors.New("Random cannot process empty endpoints")
	}

	rd.logger.Debug("Random is observing...")
	t1 := time.Now()

	es := common.ObserveEndpoints{}

	for _, e := range sr.Endpoints.Items() {

		if e == nil {
			continue
		}

		uri := common.NormalizeURI(e.URI)
		countries := make(common.ObserveCountries)

		for _, c := range e.Countries {

			value := rd.options.Min + rand.Float64()*(rd.options.Max-rd.options.Min)
			country := common.NormalizeCountry(c)
			countries[country] = &value
		}

		if len(countries) == 0 {
			continue
		}

		time.Sleep(time.Duration(rd.options.Delay) * time.Millisecond)

		e := &common.ObserveEndpoint{
			URI:       uri,
			Countries: countries,
			IPs:       e.IPs,
			Response:  e.Response,
		}
		es.Add(e)
	}

	rd.logger.Debug("Random data generated in %s", time.Since(t1))

	r := &common.ObserveResult{
		Endpoints: es,
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
