package common

import (
	"math"
	"testing"
)

// pipeline_test.go — end-to-end scenarios testing data flow through
// SourceItems.Reduce → ObserveItems.Reduce → VerifyItems.Reduce

func ptrObserve(v float64) *ObserveProbability { p := ObserveProbability(v); return &p }
func ptrVerify(v float64) *VerifyProbability   { p := VerifyProbability(v); return &p }

// Scenario 1: Happy path — single domain, two countries
func TestPipeline_HappyPath(t *testing.T) {
	// Source: 2 entries for same domain with different countries
	var src SourceItems
	src.Add(
		&SourceItem{URI: "https://domain.com", Countries: []string{"TH", "US"}},
		&SourceItem{URI: "https://domain.com", Countries: []string{"TH", "VN"}},
	)

	reduced := src.Reduce()
	if len(reduced.Items()) != 1 {
		t.Fatalf("SourceItems.Reduce() = %d items, want 1", len(reduced.Items()))
	}

	// Simulate observer output for reduced domain
	ep := reduced.Items()[0]
	var obs ObserveItems
	obs.Add(&ObserveItem{
		Key:       ep.EntryKey(),
		Countries: ObserveCountries{"TH": ptrObserve(0.8), "US": ptrObserve(0.6), "VN": ptrObserve(0.0)},
	})

	obsReduced := obs.Reduce()
	obsItems := obsReduced.Items()
	if len(obsItems) != 1 {
		t.Fatalf("ObserveItems.Reduce() = %d items, want 1", len(obsItems))
	}

	oi := obsItems[0].(*ObserveItem)
	if oi.Countries["VN"] == nil || *oi.Countries["VN"] != 0.0 {
		t.Error("VN probability 0.0 should be preserved through pipeline")
	}

	// Simulate verifier output
	var ver VerifyItems
	ver.Add(&VerifyItem{
		Key: ep.EntryKey(),
		Countries: VerifyCountries{
			"TH": &VerifyStatus{Probability: ptrVerify(0.9), Flags: VerifyStatusFlags{"wrong_ip_address": true}},
			"US": &VerifyStatus{Probability: ptrVerify(0.7)},
		},
	})

	verReduced := ver.Reduce()
	verItems := verReduced.Items()
	if len(verItems) != 1 {
		t.Fatalf("VerifyItems.Reduce() = %d items, want 1", len(verItems))
	}

	vi := verItems[0].(*VerifyItem)
	if !vi.Countries["TH"].Flags["wrong_ip_address"] {
		t.Error("wrong_ip_address flag should be preserved through pipeline")
	}
}

// Scenario 2: Multiple observers produce different probabilities → avg
func TestPipeline_MultipleObservers(t *testing.T) {
	var obs ObserveItems
	obs.Add(
		&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": ptrObserve(0.6)}},
		&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": ptrObserve(0.8)}},
	)

	r := obs.Reduce()
	oi := r.Items()[0].(*ObserveItem)
	avg := *oi.Countries["TH"]
	if math.Abs(avg-0.7) > 1e-9 {
		t.Errorf("avg probability = %f, want 0.7", avg)
	}
}

// Scenario 3: Multiple verifiers with different flags → all merged
func TestPipeline_MergeVerifierFlags(t *testing.T) {
	var ver VerifyItems
	p := VerifyProbability(0.5)
	ver.Add(
		&VerifyItem{Key: "domain.com", Countries: VerifyCountries{
			"TH": &VerifyStatus{Probability: &p, Flags: VerifyStatusFlags{"wrong_ip_address": true}},
		}},
		&VerifyItem{Key: "domain.com", Countries: VerifyCountries{
			"TH": &VerifyStatus{Probability: &p, Flags: VerifyStatusFlags{"wrong_response_code": true}},
		}},
	)

	r := ver.Reduce()
	vi := r.Items()[0].(*VerifyItem)
	if len(vi.Countries["TH"].Flags) != 2 {
		t.Errorf("merged flags count = %d, want 2", len(vi.Countries["TH"].Flags))
	}
}

// Scenario 4: Empty pipeline — no source items
func TestPipeline_EmptySource(t *testing.T) {
	var src SourceItems
	r := src.Reduce()
	if !r.IsEmpty() {
		t.Error("Reduce of empty SourceItems should be empty")
	}

	var obs ObserveItems
	or := obs.Reduce()
	if !or.IsEmpty() {
		t.Error("Reduce of empty ObserveItems should be empty")
	}

	var ver VerifyItems
	vr := ver.Reduce()
	if !vr.IsEmpty() {
		t.Error("Reduce of empty VerifyItems should be empty")
	}
}

// Scenario 5: Key-based grouping — different keys stay separate
func TestPipeline_KeyBasedGrouping(t *testing.T) {
	var src SourceItems
	src.Add(
		&SourceItem{Key: "deposit", Countries: []string{"TH"}},
		&SourceItem{Key: "withdraw", Countries: []string{"US"}},
		&SourceItem{Key: "deposit", Countries: []string{"VN"}},
	)

	r := src.Reduce()
	if len(r.Items()) != 2 {
		t.Fatalf("Reduce() = %d items, want 2 (deposit+withdraw)", len(r.Items()))
	}

	// Verify both groups exist
	keys := make(map[string]bool)
	for _, item := range r.Items() {
		keys[item.EntryKey()] = true
	}
	if !keys["deposit"] || !keys["withdraw"] {
		t.Errorf("expected both 'deposit' and 'withdraw' keys, got %v", keys)
	}
}

// Scenario 6: Nil probabilities throughout pipeline
func TestPipeline_NilProbabilities(t *testing.T) {
	// Observer returns nil probability for a country
	var obs ObserveItems
	obs.Add(
		&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": nil}},
		&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": nil}},
	)

	r := obs.Reduce()
	if len(r.Items()) != 1 {
		t.Fatalf("Reduce() = %d items, want 1", len(r.Items()))
	}

	oi := r.Items()[0].(*ObserveItem)
	if _, ok := oi.Countries["TH"]; ok {
		t.Error("all-nil probabilities should exclude the country from result")
	}

	// Verifier returns nil probability
	var ver VerifyItems
	ver.Add(
		&VerifyItem{Key: "domain.com", Countries: VerifyCountries{
			"TH": &VerifyStatus{Probability: nil},
		}},
	)

	vr := ver.Reduce()
	vi := vr.Items()[0].(*VerifyItem)
	if _, ok := vi.Countries["TH"]; ok {
		t.Error("nil verify probability should exclude country from result")
	}
}
