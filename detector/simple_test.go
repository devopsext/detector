package detector

import (
	"context"
	"sync"
	"testing"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
)

// --- No-op logger for tests ---

type testLogger struct{}

func (t *testLogger) Info(_ interface{}, _ ...interface{}) sreCommon.Logger  { return t }
func (t *testLogger) Warn(_ interface{}, _ ...interface{}) sreCommon.Logger  { return t }
func (t *testLogger) Error(_ interface{}, _ ...interface{}) sreCommon.Logger { return t }
func (t *testLogger) Debug(_ interface{}, _ ...interface{}) sreCommon.Logger { return t }
func (t *testLogger) Panic(_ interface{}, _ ...interface{})                  {}
func (t *testLogger) Stack(_ int) sreCommon.Logger                           { return t }
func (t *testLogger) Stop()                                                  {}
func (t *testLogger) SpanInfo(_ sreCommon.TracerSpan, _ interface{}, _ ...interface{}) sreCommon.Logger {
	return t
}
func (t *testLogger) SpanWarn(_ sreCommon.TracerSpan, _ interface{}, _ ...interface{}) sreCommon.Logger {
	return t
}
func (t *testLogger) SpanError(_ sreCommon.TracerSpan, _ interface{}, _ ...interface{}) sreCommon.Logger {
	return t
}
func (t *testLogger) SpanDebug(_ sreCommon.TracerSpan, _ interface{}, _ ...interface{}) sreCommon.Logger {
	return t
}
func (t *testLogger) SpanPanic(_ sreCommon.TracerSpan, _ interface{}, _ ...interface{}) {}

func nopLogger() sreCommon.Logger { return &testLogger{} }

// --- Mock Source ---

type mockSource struct {
	name string
	load func() (*common.SourceResult, error)
}

func (m *mockSource) Name() string                        { return m.name }
func (m *mockSource) Start(_ context.Context) error       { return nil }
func (m *mockSource) Load() (*common.SourceResult, error) { return m.load() }

// --- Mock Observer ---

type mockObserver struct {
	name    string
	observe func(sr *common.SourceResult) (*common.ObserveResult, error)
}

func (m *mockObserver) Name() string { return m.name }
func (m *mockObserver) Observe(sr *common.SourceResult) (*common.ObserveResult, error) {
	return m.observe(sr)
}

// --- Mock Verifier ---

type mockVerifier struct {
	name   string
	verify func(or *common.ObserveResult) (*common.VerifyResult, error)
}

func (m *mockVerifier) Name() string { return m.name }
func (m *mockVerifier) Verify(or *common.ObserveResult) (*common.VerifyResult, error) {
	return m.verify(or)
}

// --- Mock Notifier ---

type mockNotifier struct {
	name     string
	notified []*common.VerifyResult
	mu       sync.Mutex
}

func (m *mockNotifier) Name() string { return m.name }
func (m *mockNotifier) Notify(vr *common.VerifyResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notified = append(m.notified, vr)
	return nil
}

// --- Helpers ---

func pObs(v float64) *common.ObserveProbability { p := common.ObserveProbability(v); return &p }
func pVer(v float64) *common.VerifyProbability  { p := common.VerifyProbability(v); return &p }

func newSimple(opts *SimpleOptions) *Simple {
	return &Simple{
		options: opts,
		logger:  nopLogger(),
		lock:    &sync.Mutex{},
	}
}

// ===================================================================
// Tests
// ===================================================================

// Test 1: Full happy-path pipeline: Load → Observe → Verify → Notify
func TestSimple_Detect_HappyPath(t *testing.T) {
	notifier := &mockNotifier{name: "slack"}

	s := newSimple(&SimpleOptions{
		Name: "test",
		Sources: []common.Source{
			&mockSource{name: "pubsub", load: func() (*common.SourceResult, error) {
				sr := &common.SourceResult{}
				sr.Items.Add(&common.SourceItem{Key: "domain.com", Countries: []string{"TH"}})
				return sr, nil
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{
			{Observer: &mockObserver{name: "dd", observe: func(sr *common.SourceResult) (*common.ObserveResult, error) {
				or := &common.ObserveResult{}
				or.Items.Add(&common.ObserveItem{Key: "domain.com", Countries: common.ObserveCountries{"TH": pObs(0.8)}})
				return or, nil
			}}, Probability: 0.5},
		},
		VerifierConfigurations: []*common.VerifierConfiguration{
			{Verifier: &mockVerifier{name: "cp", verify: func(or *common.ObserveResult) (*common.VerifyResult, error) {
				vr := &common.VerifyResult{}
				vr.Items.Add(&common.VerifyItem{Key: "domain.com", Countries: common.VerifyCountries{
					"TH": &common.VerifyStatus{Probability: pVer(0.9)},
				}})
				return vr, nil
			}}, Probability: 0.5},
		},
		NotifierConfigurations: []*common.NotifierConfiguration{
			{Notifier: notifier, Probability: 0.0},
		},
	})

	err := s.Detect()
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(notifier.notified) == 0 {
		t.Error("Notifier was not called in happy path")
	}
}

// Test 2: No source items → Detect should return nil, no observe/verify/notify
func TestSimple_Detect_EmptySourceResult(t *testing.T) {
	notifier := &mockNotifier{name: "slack"}

	s := newSimple(&SimpleOptions{
		Name: "test",
		Sources: []common.Source{
			&mockSource{name: "src", load: func() (*common.SourceResult, error) {
				return &common.SourceResult{}, nil
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{
			{Observer: &mockObserver{name: "dd", observe: func(sr *common.SourceResult) (*common.ObserveResult, error) {
				t.Error("Observer should not be called when source is empty")
				return nil, nil
			}}, Probability: 0.5},
		},
		NotifierConfigurations: []*common.NotifierConfiguration{
			{Notifier: notifier},
		},
	})

	err := s.Detect()
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
}

// Test 3: Observer probability below threshold → filtered out, no verify/notify
func TestSimple_Detect_ObserveThresholdFilters(t *testing.T) {
	notifier := &mockNotifier{name: "slack"}

	s := newSimple(&SimpleOptions{
		Name: "test",
		Sources: []common.Source{
			&mockSource{name: "src", load: func() (*common.SourceResult, error) {
				sr := &common.SourceResult{}
				sr.Items.Add(&common.SourceItem{Key: "domain.com", Countries: []string{"TH"}})
				return sr, nil
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{
			{Observer: &mockObserver{name: "dd", observe: func(sr *common.SourceResult) (*common.ObserveResult, error) {
				or := &common.ObserveResult{}
				or.Items.Add(&common.ObserveItem{Key: "domain.com", Countries: common.ObserveCountries{"TH": pObs(0.3)}})
				return or, nil
			}}, Probability: 0.5}, // threshold 0.5, returned 0.3 → filtered
		},
		VerifierConfigurations: []*common.VerifierConfiguration{
			{Verifier: &mockVerifier{name: "cp", verify: func(or *common.ObserveResult) (*common.VerifyResult, error) {
				t.Error("Verifier should not be called when observe is below threshold")
				return nil, nil
			}}, Probability: 0.3},
		},
		NotifierConfigurations: []*common.NotifierConfiguration{
			{Notifier: notifier},
		},
	})

	err := s.Detect()
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(notifier.notified) > 0 {
		t.Error("Notifier should not be called when observe is below threshold")
	}
}

// Test 4: Disabled source items are filtered
func TestSimple_Detect_DisabledItemsFiltered(t *testing.T) {
	observerCalled := false
	s := newSimple(&SimpleOptions{
		Name: "test",
		Sources: []common.Source{
			&mockSource{name: "src", load: func() (*common.SourceResult, error) {
				sr := &common.SourceResult{}
				sr.Items.Add(&common.SourceItem{Key: "domain.com", Disabled: true})
				return sr, nil
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{
			{Observer: &mockObserver{name: "dd", observe: func(sr *common.SourceResult) (*common.ObserveResult, error) {
				observerCalled = true
				return nil, nil
			}}, Probability: 0.0},
		},
		NotifierConfigurations: []*common.NotifierConfiguration{},
	})

	s.Detect()
	if observerCalled {
		t.Error("Observer should not be called for disabled items")
	}
}

// Test 5: Detector name filtering — item with specific detector list should skip non-matching detector
func TestSimple_Detect_DetectorNameFilter(t *testing.T) {
	s := newSimple(&SimpleOptions{
		Name: "MyDetector",
		Sources: []common.Source{
			&mockSource{name: "src", load: func() (*common.SourceResult, error) {
				sr := &common.SourceResult{}
				sr.Items.Add(&common.SourceItem{Key: "domain.com", Detectors: []string{"OtherDetector"}})
				return sr, nil
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{
			{Observer: &mockObserver{name: "dd", observe: func(sr *common.SourceResult) (*common.ObserveResult, error) {
				if len(sr.Items.Items()) > 0 {
					t.Error("Source items with wrong detector should be filtered")
				}
				return nil, nil
			}}, Probability: 0.0},
		},
		NotifierConfigurations: []*common.NotifierConfiguration{},
	})

	s.Detect()
}

// Test 6: Country intersection filtering
func TestSimple_Detect_CountryFilter(t *testing.T) {
	var observedSR *common.SourceResult
	s := newSimple(&SimpleOptions{
		Name:      "test",
		Countries: []string{"TH", "VN"},
		Sources: []common.Source{
			&mockSource{name: "src", load: func() (*common.SourceResult, error) {
				sr := &common.SourceResult{}
				sr.Items.Add(&common.SourceItem{Key: "domain.com", Countries: []string{"TH", "US", "VN", "BR"}})
				return sr, nil
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{
			{Observer: &mockObserver{name: "dd", observe: func(sr *common.SourceResult) (*common.ObserveResult, error) {
				observedSR = sr
				return nil, nil
			}}, Probability: 0.0},
		},
		NotifierConfigurations: []*common.NotifierConfiguration{},
	})

	s.Detect()

	if observedSR != nil {
		for _, entry := range observedSR.Items.Items() {
			countries := entry.EntryCountries()
			for _, c := range countries {
				if c != "TH" && c != "VN" {
					t.Errorf("Country %q should be filtered out, only TH and VN expected", c)
				}
			}
		}
	}
}

// Test 7: Verify probability threshold filtering
func TestSimple_Detect_VerifyThresholdFilters(t *testing.T) {
	notifier := &mockNotifier{name: "slack"}

	s := newSimple(&SimpleOptions{
		Name: "test",
		Sources: []common.Source{
			&mockSource{name: "src", load: func() (*common.SourceResult, error) {
				sr := &common.SourceResult{}
				sr.Items.Add(&common.SourceItem{Key: "domain.com", Countries: []string{"TH"}})
				return sr, nil
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{
			{Observer: &mockObserver{name: "dd", observe: func(sr *common.SourceResult) (*common.ObserveResult, error) {
				or := &common.ObserveResult{}
				or.Items.Add(&common.ObserveItem{Key: "domain.com", Countries: common.ObserveCountries{"TH": pObs(0.8)}})
				return or, nil
			}}, Probability: 0.5},
		},
		VerifierConfigurations: []*common.VerifierConfiguration{
			{Verifier: &mockVerifier{name: "cp", verify: func(or *common.ObserveResult) (*common.VerifyResult, error) {
				vr := &common.VerifyResult{}
				vr.Items.Add(&common.VerifyItem{Key: "domain.com", Countries: common.VerifyCountries{
					"TH": &common.VerifyStatus{Probability: pVer(0.3)}, // below threshold
				}})
				return vr, nil
			}}, Probability: 0.5}, // threshold 0.5
		},
		NotifierConfigurations: []*common.NotifierConfiguration{
			{Notifier: notifier, Probability: 0.0},
		},
	})

	err := s.Detect()
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(notifier.notified) > 0 {
		t.Error("Notifier should not be called when verify probability is below threshold")
	}
}

// Test 8: Notifier probability threshold
func TestSimple_Detect_NotifyThresholdFilters(t *testing.T) {
	notifier := &mockNotifier{name: "slack"}

	s := newSimple(&SimpleOptions{
		Name: "test",
		Sources: []common.Source{
			&mockSource{name: "src", load: func() (*common.SourceResult, error) {
				sr := &common.SourceResult{}
				sr.Items.Add(&common.SourceItem{Key: "domain.com", Countries: []string{"TH"}})
				return sr, nil
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{
			{Observer: &mockObserver{name: "dd", observe: func(sr *common.SourceResult) (*common.ObserveResult, error) {
				or := &common.ObserveResult{}
				or.Items.Add(&common.ObserveItem{Key: "domain.com", Countries: common.ObserveCountries{"TH": pObs(0.8)}})
				return or, nil
			}}, Probability: 0.0},
		},
		VerifierConfigurations: []*common.VerifierConfiguration{
			{Verifier: &mockVerifier{name: "cp", verify: func(or *common.ObserveResult) (*common.VerifyResult, error) {
				vr := &common.VerifyResult{}
				vr.Items.Add(&common.VerifyItem{Key: "domain.com", Countries: common.VerifyCountries{
					"TH": &common.VerifyStatus{Probability: pVer(0.4)},
				}})
				return vr, nil
			}}, Probability: 0.0},
		},
		NotifierConfigurations: []*common.NotifierConfiguration{
			{Notifier: notifier, Probability: 0.5}, // threshold 0.5, verify returned 0.4
		},
	})

	err := s.Detect()
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(notifier.notified) > 0 {
		t.Error("Notifier should not be called when verify probability is below notifier threshold")
	}
}

// Test 9: Trigger deduplication — second Detect call shouldn't re-notify
func TestSimple_Detect_TriggerDeduplication(t *testing.T) {
	notifier := &mockNotifier{name: "slack"}
	triggers := common.NewTriggers(&common.TriggerOptions{TTL: "1h"}, common.NewObservability(nil, nil))

	opts := &SimpleOptions{
		Name:     "test",
		Triggers: triggers,
		Sources: []common.Source{
			&mockSource{name: "src", load: func() (*common.SourceResult, error) {
				sr := &common.SourceResult{}
				sr.Items.Add(&common.SourceItem{Key: "domain.com", Countries: []string{"TH"}})
				return sr, nil
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{
			{Observer: &mockObserver{name: "dd", observe: func(sr *common.SourceResult) (*common.ObserveResult, error) {
				or := &common.ObserveResult{}
				or.Items.Add(&common.ObserveItem{Key: "domain.com", Countries: common.ObserveCountries{"TH": pObs(0.8)}})
				return or, nil
			}}, Probability: 0.0},
		},
		VerifierConfigurations: []*common.VerifierConfiguration{
			{Verifier: &mockVerifier{name: "cp", verify: func(or *common.ObserveResult) (*common.VerifyResult, error) {
				vr := &common.VerifyResult{}
				vr.Items.Add(&common.VerifyItem{Key: "domain.com", Countries: common.VerifyCountries{
					"TH": &common.VerifyStatus{Probability: pVer(0.9)},
				}})
				return vr, nil
			}}, Probability: 0.0},
		},
		NotifierConfigurations: []*common.NotifierConfiguration{
			{Notifier: notifier, Probability: 0.0},
		},
	}

	s := newSimple(opts)

	// First Detect — should notify
	s.Detect()
	if len(notifier.notified) != 1 {
		t.Fatalf("First Detect: notified %d times, want 1", len(notifier.notified))
	}

	// Second Detect — trigger exists, should NOT notify again
	s.Detect()
	if len(notifier.notified) != 1 {
		t.Errorf("Second Detect: notified %d times, want 1 (deduplicated)", len(notifier.notified))
	}
}

// Test 10: Concurrency lock — second Detect fails while first is in progress
func TestSimple_Detect_ConcurrencyLock(t *testing.T) {
	started := make(chan struct{})
	proceed := make(chan struct{})

	s := newSimple(&SimpleOptions{
		Name: "test",
		Sources: []common.Source{
			&mockSource{name: "src", load: func() (*common.SourceResult, error) {
				started <- struct{}{}
				<-proceed // block until test signals
				sr := &common.SourceResult{}
				sr.Items.Add(&common.SourceItem{Key: "domain.com"})
				return sr, nil
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{
			{Observer: &mockObserver{name: "dd", observe: func(sr *common.SourceResult) (*common.ObserveResult, error) {
				return nil, nil
			}}, Probability: 0.0},
		},
		NotifierConfigurations: []*common.NotifierConfiguration{},
	})

	// Start first Detect in goroutine — will block in Load
	go func() {
		s.Detect()
	}()

	<-started // wait for first Detect to acquire the lock

	// Second Detect should fail immediately because lock is held
	err := s.Detect()
	if err == nil {
		t.Error("Second concurrent Detect() should return an error")
	}

	// Unblock the first goroutine
	close(proceed)
}

// Test 11: Multiple sources merge into one SourceResult
func TestSimple_Detect_MultipleSources(t *testing.T) {
	notifier := &mockNotifier{name: "slack"}

	s := newSimple(&SimpleOptions{
		Name: "test",
		Sources: []common.Source{
			&mockSource{name: "src1", load: func() (*common.SourceResult, error) {
				sr := &common.SourceResult{}
				sr.Items.Add(&common.SourceItem{Key: "domain.com", Countries: []string{"TH"}})
				return sr, nil
			}},
			&mockSource{name: "src2", load: func() (*common.SourceResult, error) {
				sr := &common.SourceResult{}
				sr.Items.Add(&common.SourceItem{Key: "domain.com", Countries: []string{"US"}})
				return sr, nil
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{
			{Observer: &mockObserver{name: "dd", observe: func(sr *common.SourceResult) (*common.ObserveResult, error) {
				// After merge+reduce, should have 1 item with merged countries
				items := sr.Items.Items()
				if len(items) != 1 {
					t.Errorf("Expected 1 merged source item, got %d", len(items))
				}
				or := &common.ObserveResult{}
				or.Items.Add(&common.ObserveItem{Key: "domain.com", Countries: common.ObserveCountries{"TH": pObs(0.8)}})
				return or, nil
			}}, Probability: 0.0},
		},
		VerifierConfigurations: []*common.VerifierConfiguration{
			{Verifier: &mockVerifier{name: "cp", verify: func(or *common.ObserveResult) (*common.VerifyResult, error) {
				vr := &common.VerifyResult{}
				vr.Items.Add(&common.VerifyItem{Key: "domain.com", Countries: common.VerifyCountries{
					"TH": &common.VerifyStatus{Probability: pVer(0.9)},
				}})
				return vr, nil
			}}, Probability: 0.0},
		},
		NotifierConfigurations: []*common.NotifierConfiguration{
			{Notifier: notifier, Probability: 0.0},
		},
	})

	err := s.Detect()
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(notifier.notified) == 0 {
		t.Error("Notifier should be called")
	}
}

// Test 12: Source with nil Load result → no crash
func TestSimple_Detect_NilSourceResult(t *testing.T) {
	s := newSimple(&SimpleOptions{
		Name: "test",
		Sources: []common.Source{
			&mockSource{name: "src", load: func() (*common.SourceResult, error) {
				return nil, nil // nil result
			}},
		},
		ObserverConfigurations: []*common.ObserverConfiguration{},
		NotifierConfigurations: []*common.NotifierConfiguration{},
	})

	err := s.Detect()
	if err != nil {
		t.Fatalf("Detect() with nil source result should not error: %v", err)
	}
}

// Test 13: Name() defaults to "Simple" when not specified
func TestSimple_Name_Default(t *testing.T) {
	s := newSimple(&SimpleOptions{})
	if s.Name() != SimpleDetectorName {
		t.Errorf("Name() = %q, want %q", s.Name(), SimpleDetectorName)
	}
}

func TestSimple_Name_Custom(t *testing.T) {
	s := newSimple(&SimpleOptions{Name: "Availability"})
	if s.Name() != "Availability" {
		t.Errorf("Name() = %q, want 'Availability'", s.Name())
	}
}
