package common

// VerifyDefaultItem is a standardized verification result for one label-group from the Default pipeline.
type VerifyDefaultItem struct {
	Labels   map[string]string
	Value    float64
	Passed   bool
	Severity string
	Details  string
}

// VerifyDefaultResult is the result returned by VerifierDefaultInterface.Verify().
// It contains one VerifyDefaultItem per label-group returned by the observer.
type VerifyDefaultResult struct {
	Items []*VerifyDefaultItem
}

func (v *VerifyDefaultResult) IsEmpty() bool {
	return len(v.Items) == 0
}

// VerifierDefaultInterface is the interface for verifiers that support the Default pipeline.
type VerifierDefaultInterface interface {
	Name() string
	VerifyDefault(out *ObserveDefaultOutput) (*VerifyDefaultResult, error)
}
