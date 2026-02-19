package common

import (
	"encoding/json"
	"math"
	"testing"
)

// mockVerifier implements Verifier for testing FindConfigurationByPattern
type mockVerifier struct{ name string }

func (m *mockVerifier) Name() string                                   { return m.name }
func (m *mockVerifier) Verify(_ *ObserveResult) (*VerifyResult, error) { return nil, nil }

// --- JSON Serialization ---

func TestVerifyItem_JSON_RoundTrip(t *testing.T) {
	p := VerifyProbability(0.75)
	orig := &VerifyItem{
		Key: "domain.com",
		Countries: VerifyCountries{
			"TH": &VerifyStatus{
				Probability: &p,
				Flags: VerifyStatusFlags{
					VerifyStatusFlagWrongIPAddress: true,
				},
			},
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got VerifyItem
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if got.Key != orig.Key {
		t.Errorf("Key = %q, want %q", got.Key, orig.Key)
	}
	if got.Countries["TH"] == nil {
		t.Fatal("Countries[TH] is nil")
	}
	if got.Countries["TH"].Probability == nil || *got.Countries["TH"].Probability != 0.75 {
		t.Error("Countries[TH].Probability != 0.75")
	}
	if !got.Countries["TH"].Flags[VerifyStatusFlagWrongIPAddress] {
		t.Error("Flags[wrong_ip_address] != true")
	}
}

func TestVerifyItem_JSON_NilProbability(t *testing.T) {
	orig := &VerifyItem{
		Key:       "x.com",
		Countries: VerifyCountries{"TH": &VerifyStatus{Probability: nil}},
	}

	data, _ := json.Marshal(orig)
	var got VerifyItem
	json.Unmarshal(data, &got)

	if got.Countries["TH"].Probability != nil {
		t.Error("expected nil probability after round-trip")
	}
}

func TestVerifyItem_JSON_OmitEmpty(t *testing.T) {
	si := &VerifyItem{URI: "https://domain.com"}
	data, _ := json.Marshal(si)
	s := string(data)

	var m map[string]interface{}
	json.Unmarshal([]byte(s), &m)
	if _, ok := m["key"]; ok {
		t.Error("JSON contains 'key' but should be omitted when empty")
	}
}

// --- VerifyItems CRUD ---

func TestVerifyItems_AddAndItems(t *testing.T) {
	var items VerifyItems
	items.Add(&VerifyItem{Key: "a"})
	if len(items.Items()) != 1 {
		t.Fatalf("len(Items()) = %d, want 1", len(items.Items()))
	}
}

func TestVerifyItems_IsEmpty(t *testing.T) {
	var items VerifyItems
	if !items.IsEmpty() {
		t.Error("IsEmpty() = false, want true")
	}
	items.Add(&VerifyItem{Key: "a"})
	if items.IsEmpty() {
		t.Error("IsEmpty() = true, want false")
	}
}

// --- Reduce ---

func TestVerifyItems_Reduce_SingleItem(t *testing.T) {
	var items VerifyItems
	p := VerifyProbability(0.75)
	items.Add(&VerifyItem{
		Key: "domain.com",
		Countries: VerifyCountries{
			"TH": &VerifyStatus{Probability: &p, Flags: VerifyStatusFlags{"wrong_ip_address": true}},
		},
	})

	r := items.Reduce()
	got := r.Items()
	if len(got) != 1 {
		t.Fatalf("Reduce() produced %d items, want 1", len(got))
	}

	vi := got[0].(*VerifyItem)
	if vi.Countries["TH"].Probability == nil || *vi.Countries["TH"].Probability != 0.75 {
		t.Error("probability mismatch")
	}
	if !vi.Countries["TH"].Flags["wrong_ip_address"] {
		t.Error("flag missing")
	}
}

func TestVerifyItems_Reduce_AvgProbability(t *testing.T) {
	var items VerifyItems
	p1 := VerifyProbability(0.4)
	p2 := VerifyProbability(0.8)
	items.Add(
		&VerifyItem{Key: "d.com", Countries: VerifyCountries{"TH": &VerifyStatus{Probability: &p1}}},
		&VerifyItem{Key: "d.com", Countries: VerifyCountries{"TH": &VerifyStatus{Probability: &p2}}},
	)

	r := items.Reduce()
	vi := r.Items()[0].(*VerifyItem)
	avg := *vi.Countries["TH"].Probability
	want := 0.6
	if math.Abs(avg-want) > 1e-9 {
		t.Errorf("avg = %f, want %f", avg, want)
	}
}

func TestVerifyItems_Reduce_NilProbabilitySkipped(t *testing.T) {
	var items VerifyItems
	p := VerifyProbability(0.6)
	items.Add(
		&VerifyItem{Key: "d.com", Countries: VerifyCountries{"TH": &VerifyStatus{Probability: &p}}},
		&VerifyItem{Key: "d.com", Countries: VerifyCountries{"TH": &VerifyStatus{Probability: nil}}},
	)

	r := items.Reduce()
	vi := r.Items()[0].(*VerifyItem)
	if vi.Countries["TH"] == nil || *vi.Countries["TH"].Probability != 0.6 {
		t.Error("nil probability should be skipped, avg = 0.6")
	}
}

func TestVerifyItems_Reduce_AllNilProbability_CountryExcluded(t *testing.T) {
	var items VerifyItems
	items.Add(
		&VerifyItem{Key: "d.com", Countries: VerifyCountries{"TH": &VerifyStatus{Probability: nil}}},
		&VerifyItem{Key: "d.com", Countries: VerifyCountries{"TH": &VerifyStatus{Probability: nil}}},
	)

	r := items.Reduce()
	vi := r.Items()[0].(*VerifyItem)
	if _, ok := vi.Countries["TH"]; ok {
		t.Error("country with all nil probabilities should be excluded")
	}
}

func TestVerifyItems_Reduce_ZeroProbability(t *testing.T) {
	var items VerifyItems
	p := VerifyProbability(0.0)
	items.Add(&VerifyItem{Key: "d.com", Countries: VerifyCountries{"TH": &VerifyStatus{Probability: &p}}})

	r := items.Reduce()
	vi := r.Items()[0].(*VerifyItem)
	if vi.Countries["TH"] == nil || *vi.Countries["TH"].Probability != 0.0 {
		t.Error("0.0 probability should be preserved")
	}
}

func TestVerifyItems_Reduce_ProbabilityOne(t *testing.T) {
	var items VerifyItems
	p := VerifyProbability(1.0)
	items.Add(&VerifyItem{Key: "d.com", Countries: VerifyCountries{"TH": &VerifyStatus{Probability: &p}}})

	r := items.Reduce()
	vi := r.Items()[0].(*VerifyItem)
	if vi.Countries["TH"] == nil || *vi.Countries["TH"].Probability != 1.0 {
		t.Error("1.0 probability should be preserved")
	}
}

func TestVerifyItems_Reduce_MergeFlags(t *testing.T) {
	var items VerifyItems
	p := VerifyProbability(0.5)
	items.Add(
		&VerifyItem{Key: "d.com", Countries: VerifyCountries{
			"TH": &VerifyStatus{Probability: &p, Flags: VerifyStatusFlags{"wrong_ip_address": true}},
		}},
		&VerifyItem{Key: "d.com", Countries: VerifyCountries{
			"TH": &VerifyStatus{Probability: &p, Flags: VerifyStatusFlags{"wrong_response_code": true}},
		}},
	)

	r := items.Reduce()
	vi := r.Items()[0].(*VerifyItem)
	flags := vi.Countries["TH"].Flags
	if !flags["wrong_ip_address"] {
		t.Error("missing flag wrong_ip_address after merge")
	}
	if !flags["wrong_response_code"] {
		t.Error("missing flag wrong_response_code after merge")
	}
}

func TestVerifyItems_Reduce_FlagFalseNotMerged(t *testing.T) {
	var items VerifyItems
	p := VerifyProbability(0.5)
	items.Add(
		&VerifyItem{Key: "d.com", Countries: VerifyCountries{
			"TH": &VerifyStatus{Probability: &p, Flags: VerifyStatusFlags{"wrong_ip_address": false}},
		}},
	)

	r := items.Reduce()
	vi := r.Items()[0].(*VerifyItem)
	if vi.Countries["TH"].Flags["wrong_ip_address"] {
		t.Error("flag with false value should not be merged as true")
	}
}

func TestVerifyItems_Reduce_CountryNormalization(t *testing.T) {
	var items VerifyItems
	p := VerifyProbability(0.5)
	items.Add(&VerifyItem{Key: "d.com", Countries: VerifyCountries{
		"th": &VerifyStatus{Probability: &p},
	}})

	r := items.Reduce()
	vi := r.Items()[0].(*VerifyItem)
	if _, ok := vi.Countries["TH"]; !ok {
		t.Error("country should be normalized to uppercase")
	}
}

func TestVerifyItems_Reduce_NilStatus_Skipped(t *testing.T) {
	var items VerifyItems
	p := VerifyProbability(0.5)
	items.Add(&VerifyItem{Key: "d.com", Countries: VerifyCountries{
		"TH": nil,
		"US": &VerifyStatus{Probability: &p},
	}})

	r := items.Reduce()
	vi := r.Items()[0].(*VerifyItem)
	if _, ok := vi.Countries["TH"]; ok {
		t.Error("nil VerifyStatus should be skipped")
	}
	if vi.Countries["US"] == nil {
		t.Error("US should be present")
	}
}

func TestVerifyItems_Reduce_DifferentKeys(t *testing.T) {
	var items VerifyItems
	p := VerifyProbability(0.5)
	items.Add(
		&VerifyItem{Key: "a", Countries: VerifyCountries{"TH": &VerifyStatus{Probability: &p}}},
		&VerifyItem{Key: "b", Countries: VerifyCountries{"TH": &VerifyStatus{Probability: &p}}},
	)

	r := items.Reduce()
	if len(r.Items()) != 2 {
		t.Errorf("Reduce() produced %d items, want 2 (different keys)", len(r.Items()))
	}
}

func TestVerifyItems_Reduce_Empty(t *testing.T) {
	var items VerifyItems
	r := items.Reduce()
	if !r.IsEmpty() {
		t.Error("Reduce() of empty should be empty")
	}
}

func TestVerifyItems_Reduce_NilEntry(t *testing.T) {
	var items VerifyItems
	p := VerifyProbability(0.5)
	items.Add(nil, &VerifyItem{Key: "a", Countries: VerifyCountries{"TH": &VerifyStatus{Probability: &p}}})

	r := items.Reduce()
	if len(r.Items()) != 1 {
		t.Errorf("Reduce() = %d items, want 1 (nil skipped)", len(r.Items()))
	}
}

// --- Clone ---

func TestVerifyItems_Clone_DeepCopy(t *testing.T) {
	var items VerifyItems
	p := VerifyProbability(0.5)
	orig := &VerifyItem{
		Key: "d.com",
		Countries: VerifyCountries{
			"TH": &VerifyStatus{
				Probability: &p,
				Flags:       VerifyStatusFlags{"wrong_ip_address": true},
			},
		},
	}

	cloned := items.Clone(orig)

	if cloned.Key != orig.Key {
		t.Error("Clone Key mismatch")
	}

	// Changing clone shouldn't affect original
	newP := VerifyProbability(0.9)
	cloned.Countries["TH"].Probability = &newP
	// Note: Clone shares the Flags map reference, but changes to Probability are safe
	if *orig.Countries["TH"].Probability != 0.5 {
		t.Error("Modifying clone changed original probability")
	}
}

// --- Verifiers.FindConfigurationByPattern ---

func TestVerifiers_FindConfigurationByPattern_Valid(t *testing.T) {
	vs := &Verifiers{
		logger: testLogger(),
		items:  []Verifier{&mockVerifier{"Catchpoint"}, &mockVerifier{"Site24x7"}},
	}

	got := vs.FindConfigurationByPattern("catchpoint:0.7;site24x7:0.5")
	if len(got) != 2 {
		t.Fatalf("FindConfigurationByPattern returned %d configs, want 2", len(got))
	}
	for _, c := range got {
		switch c.Verifier.Name() {
		case "Catchpoint":
			if c.Probability != 0.7 {
				t.Errorf("Catchpoint probability = %f, want 0.7", c.Probability)
			}
		case "Site24x7":
			if c.Probability != 0.5 {
				t.Errorf("Site24x7 probability = %f, want 0.5", c.Probability)
			}
		}
	}
}

func TestVerifiers_FindConfigurationByPattern_Empty(t *testing.T) {
	vs := &Verifiers{
		logger: testLogger(),
		items:  []Verifier{&mockVerifier{"Catchpoint"}},
	}

	got := vs.FindConfigurationByPattern("")
	if len(got) != 0 {
		t.Errorf("FindConfigurationByPattern('') returned %d, want 0", len(got))
	}
}

func TestVerifiers_FindConfigurationByPattern_UnknownVerifier(t *testing.T) {
	vs := &Verifiers{
		logger: testLogger(),
		items:  []Verifier{&mockVerifier{"Catchpoint"}},
	}

	got := vs.FindConfigurationByPattern("unknown:0.5")
	if len(got) != 0 {
		t.Errorf("FindConfigurationByPattern with unknown verifier returned %d, want 0", len(got))
	}
}

func TestVerifiers_FindConfigurationByPattern_InvalidFloat(t *testing.T) {
	vs := &Verifiers{
		logger: testLogger(),
		items:  []Verifier{&mockVerifier{"Catchpoint"}},
	}

	got := vs.FindConfigurationByPattern("catchpoint:abc")
	if len(got) != 0 {
		t.Errorf("FindConfigurationByPattern with invalid float returned %d, want 0", len(got))
	}
}

func TestVerifiers_GetDefaultConfigurations(t *testing.T) {
	vs := &Verifiers{
		logger: testLogger(),
		items:  []Verifier{&mockVerifier{"Catchpoint"}, &mockVerifier{"Site24x7"}},
	}

	got := vs.GetDefaultConfigurations()
	if len(got) != 2 {
		t.Fatalf("GetDefaultConfigurations returned %d configs, want 2", len(got))
	}
	for _, c := range got {
		if c.Probability != 0.0 {
			t.Errorf("default probability = %f, want 0.0", c.Probability)
		}
	}
}
