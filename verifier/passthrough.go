package verifier

import (
	"errors"
	"fmt"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
)

type Passthrough struct {
	logger sreCommon.Logger
}

const PassthroughVerifierName = "Passthrough"

func (p *Passthrough) Name() string {
	return PassthroughVerifierName
}

// Verify is a stub for the Endpoints pipeline — Passthrough only supports Default.
func (p *Passthrough) Verify(or *common.ObserveResult) (*common.VerifyResult, error) {
	return nil, errors.New("Passthrough verifier does not support Endpoints pipeline")
}

// VerifyDefault maps every observed item to a failed verification item so that
// all observations reach the notifier without any filtering.
func (p *Passthrough) VerifyDefault(out *common.ObserveDefaultOutput) (*common.VerifyDefaultResult, error) {
	if out == nil || out.IsEmpty() {
		return &common.VerifyDefaultResult{}, nil
	}

	p.logger.Debug("Passthrough verifier is processing %d items", len(out.Items))

	result := &common.VerifyDefaultResult{}
	for _, item := range out.Items {
		result.Items = append(result.Items, &common.VerifyDefaultItem{
			Labels:  item.Labels,
			Value:   item.Value,
			Passed:  false,
			Details: fmt.Sprintf("passthrough: value=%.4f", item.Value),
		})
	}

	return result, nil
}

func NewPassthrough(observability *common.Observability) *Passthrough {
	return &Passthrough{
		logger: observability.Logs(),
	}
}
