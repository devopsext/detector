package verifier

import (
	"errors"
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

	rd.logger.Debug("Random verified in %s", time.Since(t1))

	vs := common.VerifyEndpoints{}

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
