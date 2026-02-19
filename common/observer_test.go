package common

import (
	"encoding/json"
	"math"
	"testing"
)

// mockObserver implements Observer for testing FindConfigurationByPattern
type mockObserver struct{ name string }

func (m *mockObserver) Name() string                                    { return m.name }
func (m *mockObserver) Observe(_ *SourceResult) (*ObserveResult, error) { return nil, nil }

// --- JSON Serialization ---

func TestObserveItem_JSON_RoundTrip(t *testing.T) {
	p1 := ObserveProbability(0.8)
	p2 := ObserveProbability(0.0)
	orig := &ObserveItem{
		Key:       "payment",
		Countries: ObserveCountries{"TH": &p1, "US": &p2},
		IPs:       []string{"1.1.1.1"},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got ObserveItem
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if got.Key != orig.Key {
		t.Errorf("Key = %q, want %q", got.Key, orig.Key)
	}
	if got.Countries["TH"] == nil || *got.Countries["TH"] != 0.8 {
		t.Errorf("Countries[TH] != 0.8")
	}
	if got.Countries["US"] == nil || *got.Countries["US"] != 0.0 {
		t.Errorf("Countries[US] != 0.0 (zero should be preserved)")
	}
}

func TestObserveItem_JSON_NilProbability(t *testing.T) {
	orig := &ObserveItem{
		Key:       "x",
		Countries: ObserveCountries{"TH": nil},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got ObserveItem
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if got.Countries["TH"] != nil {
		t.Errorf("Countries[TH] = %v, want nil", got.Countries["TH"])
	}
}

// --- ObserveItems CRUD ---

func TestObserveItems_AddAndItems(t *testing.T) {
	var items ObserveItems
	p := ObserveProbability(0.5)
	items.Add(&ObserveItem{Key: "a", Countries: ObserveCountries{"TH": &p}})
	if len(items.Items()) != 1 {
		t.Fatalf("len(Items()) = %d, want 1", len(items.Items()))
	}
}

func TestObserveItems_IsEmpty(t *testing.T) {
	var items ObserveItems
	if !items.IsEmpty() {
		t.Error("IsEmpty() = false, want true")
	}
	items.Add(&ObserveItem{Key: "a"})
	if items.IsEmpty() {
		t.Error("IsEmpty() = true, want false")
	}
}

// --- Reduce ---

func TestObserveItems_Reduce_SingleItem(t *testing.T) {
	var items ObserveItems
	p := ObserveProbability(0.8)
	items.Add(&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": &p}})

	r := items.Reduce()
	got := r.Items()
	if len(got) != 1 {
		t.Fatalf("Reduce() produced %d items, want 1", len(got))
	}

	oi := got[0].(*ObserveItem)
	if oi.Countries["TH"] == nil || *oi.Countries["TH"] != 0.8 {
		t.Errorf("Countries[TH] = %v, want 0.8", oi.Countries["TH"])
	}
}

func TestObserveItems_Reduce_AvgProbability(t *testing.T) {
	var items ObserveItems
	p1 := ObserveProbability(0.6)
	p2 := ObserveProbability(0.8)
	items.Add(
		&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": &p1}},
		&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": &p2}},
	)

	r := items.Reduce()
	got := r.Items()
	if len(got) != 1 {
		t.Fatalf("Reduce() produced %d items, want 1", len(got))
	}

	oi := got[0].(*ObserveItem)
	if oi.Countries["TH"] == nil {
		t.Fatal("Countries[TH] is nil")
	}

	avg := *oi.Countries["TH"]
	want := 0.7
	if math.Abs(avg-want) > 1e-9 {
		t.Errorf("avg probability = %f, want %f", avg, want)
	}
}

func TestObserveItems_Reduce_NilProbability_Skipped(t *testing.T) {
	var items ObserveItems
	p := ObserveProbability(0.6)
	items.Add(
		&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": &p}},
		&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": nil}},
	)

	r := items.Reduce()
	got := r.Items()
	oi := got[0].(*ObserveItem)

	// nil probability should be skipped → avg = 0.6 (only one valid)
	if oi.Countries["TH"] == nil || *oi.Countries["TH"] != 0.6 {
		val := "nil"
		if oi.Countries["TH"] != nil {
			val = string(rune(int(*oi.Countries["TH"])))
		}
		t.Errorf("Countries[TH] = %v, want 0.6 (nil skipped)", val)
	}
}

func TestObserveItems_Reduce_AllNil_CountryExcluded(t *testing.T) {
	var items ObserveItems
	items.Add(
		&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": nil}},
		&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": nil}},
	)

	r := items.Reduce()
	got := r.Items()
	if len(got) != 1 {
		t.Fatalf("Reduce() produced %d items, want 1", len(got))
	}

	oi := got[0].(*ObserveItem)
	if _, ok := oi.Countries["TH"]; ok {
		t.Error("Countries[TH] should not exist when all probabilities are nil")
	}
}

func TestObserveItems_Reduce_ZeroProbability(t *testing.T) {
	var items ObserveItems
	p := ObserveProbability(0.0)
	items.Add(&ObserveItem{Key: "domain.com", Countries: ObserveCountries{"TH": &p}})

	r := items.Reduce()
	oi := r.Items()[0].(*ObserveItem)

	// 0.0 is a valid probability → should be kept
	if oi.Countries["TH"] == nil || *oi.Countries["TH"] != 0.0 {
		t.Error("0.0 probability should be preserved (not treated as nil)")
	}
}

func TestObserveItems_Reduce_MultipleCountries(t *testing.T) {
	var items ObserveItems
	pTH := ObserveProbability(0.4)
	pUS := ObserveProbability(0.9)
	items.Add(&ObserveItem{
		Key:       "domain.com",
		Countries: ObserveCountries{"th": &pTH, "us": &pUS},
	})

	r := items.Reduce()
	oi := r.Items()[0].(*ObserveItem)

	// Countries should be normalized to uppercase
	if _, ok := oi.Countries["TH"]; !ok {
		t.Error("Countries[TH] missing (country should be normalized to uppercase)")
	}
	if _, ok := oi.Countries["US"]; !ok {
		t.Error("Countries[US] missing (country should be normalized to uppercase)")
	}
}

func TestObserveItems_Reduce_MergeIPs(t *testing.T) {
	var items ObserveItems
	p := ObserveProbability(0.5)
	items.Add(
		&ObserveItem{Key: "d.com", Countries: ObserveCountries{"TH": &p}, IPs: []string{"1.1.1.1"}},
		&ObserveItem{Key: "d.com", Countries: ObserveCountries{"TH": &p}, IPs: []string{"2.2.2.2", "1.1.1.1"}},
	)

	r := items.Reduce()
	oi := r.Items()[0].(*ObserveItem)
	if len(oi.IPs) != 2 {
		t.Errorf("IPs = %v, want 2 unique IPs", oi.IPs)
	}
}

func TestObserveItems_Reduce_DifferentKeys(t *testing.T) {
	var items ObserveItems
	p := ObserveProbability(0.5)
	items.Add(
		&ObserveItem{Key: "a", Countries: ObserveCountries{"TH": &p}},
		&ObserveItem{Key: "b", Countries: ObserveCountries{"TH": &p}},
	)

	r := items.Reduce()
	if len(r.Items()) != 2 {
		t.Errorf("Reduce() produced %d items, want 2 (different keys)", len(r.Items()))
	}
}

func TestObserveItems_Reduce_Empty(t *testing.T) {
	var items ObserveItems
	r := items.Reduce()
	if !r.IsEmpty() {
		t.Error("Reduce() of empty should be empty")
	}
}

func TestObserveItems_Reduce_NilEntry(t *testing.T) {
	var items ObserveItems
	p := ObserveProbability(0.5)
	items.Add(nil, &ObserveItem{Key: "a", Countries: ObserveCountries{"TH": &p}})

	r := items.Reduce()
	if len(r.Items()) != 1 {
		t.Errorf("Reduce() produced %d items, want 1 (nil skipped)", len(r.Items()))
	}
}

func TestObserveItems_Reduce_ProbabilityOne(t *testing.T) {
	var items ObserveItems
	p := ObserveProbability(1.0)
	items.Add(&ObserveItem{Key: "d.com", Countries: ObserveCountries{"TH": &p}})

	r := items.Reduce()
	oi := r.Items()[0].(*ObserveItem)
	if oi.Countries["TH"] == nil || *oi.Countries["TH"] != 1.0 {
		t.Error("probability 1.0 should be preserved")
	}
}

// --- Clone ---

func TestObserveItems_Clone_DeepCopy(t *testing.T) {
	var items ObserveItems
	p := ObserveProbability(0.5)
	orig := &ObserveItem{
		Key:       "a",
		Countries: ObserveCountries{"TH": &p},
		IPs:       []string{"1.1.1.1"},
	}

	cloned := items.Clone(orig)

	if cloned.Key != orig.Key {
		t.Error("Clone Key mismatch")
	}

	// Changing clone probability shouldn't affect original
	newP := ObserveProbability(0.9)
	cloned.Countries["TH"] = &newP
	if *orig.Countries["TH"] != 0.5 {
		t.Error("Modifying clone changed original probability")
	}
}

// --- Observers.FindConfigurationByPattern ---

func TestObservers_FindConfigurationByPattern_Valid(t *testing.T) {
	obs := &Observers{
		logger: testLogger(),
		items:  []Observer{&mockObserver{"Datadog"}, &mockObserver{"Random"}},
	}

	got := obs.FindConfigurationByPattern("datadog:0.7;random:0.5")
	if len(got) != 2 {
		t.Fatalf("FindConfigurationByPattern returned %d configs, want 2", len(got))
	}
	for _, c := range got {
		switch c.Observer.Name() {
		case "Datadog":
			if c.Probability != 0.7 {
				t.Errorf("Datadog probability = %f, want 0.7", c.Probability)
			}
		case "Random":
			if c.Probability != 0.5 {
				t.Errorf("Random probability = %f, want 0.5", c.Probability)
			}
		default:
			t.Errorf("unexpected observer %q", c.Observer.Name())
		}
	}
}

func TestObservers_FindConfigurationByPattern_Empty(t *testing.T) {
	obs := &Observers{
		logger: testLogger(),
		items:  []Observer{&mockObserver{"Datadog"}},
	}

	got := obs.FindConfigurationByPattern("")
	if len(got) != 0 {
		t.Errorf("FindConfigurationByPattern('') returned %d configs, want 0", len(got))
	}
}

func TestObservers_FindConfigurationByPattern_UnknownObserver(t *testing.T) {
	obs := &Observers{
		logger: testLogger(),
		items:  []Observer{&mockObserver{"Datadog"}},
	}

	got := obs.FindConfigurationByPattern("prometheus:0.5")
	if len(got) != 0 {
		t.Errorf("FindConfigurationByPattern with unknown observer returned %d, want 0", len(got))
	}
}

func TestObservers_FindConfigurationByPattern_InvalidFloat(t *testing.T) {
	obs := &Observers{
		logger: testLogger(),
		items:  []Observer{&mockObserver{"Datadog"}},
	}

	got := obs.FindConfigurationByPattern("datadog:abc")
	if len(got) != 0 {
		t.Errorf("FindConfigurationByPattern with invalid float returned %d, want 0", len(got))
	}
}

func TestObservers_FindConfigurationByPattern_ZeroProbability(t *testing.T) {
	obs := &Observers{
		logger: testLogger(),
		items:  []Observer{&mockObserver{"Datadog"}},
	}

	got := obs.FindConfigurationByPattern("datadog:0")
	if len(got) != 1 {
		t.Fatalf("FindConfigurationByPattern returned %d configs, want 1", len(got))
	}
	if got[0].Probability != 0.0 {
		t.Errorf("probability = %f, want 0.0", got[0].Probability)
	}
}

func TestObservers_FindConfigurationByPattern_OneProbability(t *testing.T) {
	obs := &Observers{
		logger: testLogger(),
		items:  []Observer{&mockObserver{"Datadog"}},
	}

	got := obs.FindConfigurationByPattern("datadog:1")
	if len(got) != 1 {
		t.Fatalf("FindConfigurationByPattern returned %d configs, want 1", len(got))
	}
	if got[0].Probability != 1.0 {
		t.Errorf("probability = %f, want 1.0", got[0].Probability)
	}
}

func TestObservers_GetDefaultConfigurations(t *testing.T) {
	obs := &Observers{
		logger: testLogger(),
		items:  []Observer{&mockObserver{"Datadog"}, &mockObserver{"Random"}},
	}

	got := obs.GetDefaultConfigurations()
	if len(got) != 2 {
		t.Fatalf("GetDefaultConfigurations returned %d configs, want 2", len(got))
	}
	// Default probability should be zero value (0.0)
	for _, c := range got {
		if c.Probability != 0.0 {
			t.Errorf("default probability = %f, want 0.0", c.Probability)
		}
	}
}
