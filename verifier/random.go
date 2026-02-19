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
	metrics *common.VerifierMetrics
}

const RandomVerifierName = "Random"

func (rd *Random) Name() string {
	return RandomVerifierName
}

func (rd *Random) Verify(or *common.ObserveResult) (*common.VerifyResult, error) {

	if or.Items.IsEmpty() {
		return nil, errors.New("Random verifier cannot process empty items")
	}

	rd.logger.Debug("Random verifier is processing...")
	t1 := time.Now()

	vs := common.VerifyItems{}

	for _, entry := range or.Items.Items() {

		if entry == nil {
			continue
		}

		key := entry.EntryKey()
		countries := make(common.VerifyCountries)

		for k := range entry.EntryObserveCountries() {

			flags := make(common.VerifyStatusFlags)
			flags[common.VerifyStatusFlagWrongIPAddress] = rand.Int32N(2) == 1
			flags[common.VerifyStatusFlagWrongResponseCode] = rand.Int32N(2) == 1

			value := rd.options.Min + rand.Float64()*(rd.options.Max-rd.options.Min)
			status := &common.VerifyStatus{
				Probability: &value,
				Flags:       flags,
			}
			country := common.NormalizeCountry(k)
			countries[country] = status

			if rd.metrics != nil {
				// ExtractDomain is domain-specific; use key directly for metrics
				normalizedCountry := common.NormalizeCountryForMetrics(k)
				rd.metrics.RecordTestResult(rd.Name(), key, normalizedCountry, value, 0)
			}
		}

		if len(countries) == 0 {
			continue
		}

		time.Sleep(time.Duration(rd.options.Delay) * time.Millisecond)

		e := &common.VerifyItem{
			Key:       key,
			Countries: countries,
		}
		vs.Add(e)
	}

	rd.logger.Debug("Random verifier spent %s", time.Since(t1))

	r := &common.VerifyResult{
		Items: vs,
	}
	return r, nil
}

func NewRandom(options *RandomOptions, observability *common.Observability) *Random {

	logger := observability.Logs()

	return &Random{
		options: options,
		logger:  logger,
		metrics: common.NewVerifierMetrics(observability.Metrics()),
	}
}
