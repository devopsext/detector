package verifier

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
	logger  sreCommon.Logger
	options *RandomOptions
}

const RandomVerifierName = "Random"

func (rd *Random) Name() string {
	return RandomVerifierName
}

func (rd *Random) Verify(or *common.ObserveResult) (*common.VerifyResult, error) {

	if or.Endpoints.IsEmpty() {
		return nil, errors.New("Random cannot process empty endpoints")
	}

	rd.logger.Debug("Random is verifying...")
	t1 := time.Now()

	vs := common.VerifyEndpoints{}

	for _, e := range or.Endpoints.Items() {

		if e == nil {
			continue
		}

		uri := common.NormalizeURI(e.URI)
		countries := make(common.VerifyCountries)

		for k := range e.Countries {

			value := rd.options.Min + rand.Float64()*(rd.options.Max-rd.options.Min)
			status := &common.VerifyStatus{
				Probability: &value,
			}
			country := common.NormalizeCountry(k)
			countries[country] = status
		}

		if len(countries) == 0 {
			continue
		}

		time.Sleep(time.Duration(rd.options.Delay) * time.Millisecond)

		e := &common.VerifyEndpoint{
			URI:       uri,
			Countries: countries,
		}
		vs.Add(e)
	}

	rd.logger.Debug("Random verified in %s", time.Since(t1))

	r := &common.VerifyResult{
		Endpoints: vs,
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
