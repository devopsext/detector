package common

import (
	"testing"
)

// Compile-time interface checks
var _ SourceEntry = (*SourceItem)(nil)
var _ ObserveEntry = (*ObserveItem)(nil)
var _ VerifyEntry = (*VerifyItem)(nil)

// --- SourceItem.EntryKey ---

func TestSourceItem_EntryKey_FromURI(t *testing.T) {
	si := &SourceItem{URI: "https://Domain.COM/path"}
	got := si.EntryKey()
	want := "https://domain.com/path" // NormalizeURI = strings.ToLower
	if got != want {
		t.Errorf("EntryKey() = %q, want %q", got, want)
	}
}

func TestSourceItem_EntryKey_ExplicitKey(t *testing.T) {
	si := &SourceItem{Key: "payment"}
	if got := si.EntryKey(); got != "payment" {
		t.Errorf("EntryKey() = %q, want %q", got, "payment")
	}
}

func TestSourceItem_EntryKey_BothKeyAndURI(t *testing.T) {
	si := &SourceItem{Key: "deposit", URI: "https://x.com"}
	if got := si.EntryKey(); got != "deposit" {
		t.Errorf("EntryKey() = %q, want %q (Key should take priority over URI)", got, "deposit")
	}
}

func TestSourceItem_EntryKey_Empty(t *testing.T) {
	si := &SourceItem{}
	if got := si.EntryKey(); got != "" {
		t.Errorf("EntryKey() = %q, want %q", got, "")
	}
}

func TestSourceItem_EntryIdent_EqualsEntryKey(t *testing.T) {
	cases := []struct {
		name string
		item *SourceItem
	}{
		{"with key", &SourceItem{Key: "deposit"}},
		{"with uri", &SourceItem{URI: "https://domain.com"}},
		{"empty", &SourceItem{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.item.EntryIdent() != tc.item.EntryKey() {
				t.Errorf("EntryIdent() = %q, want EntryKey() = %q", tc.item.EntryIdent(), tc.item.EntryKey())
			}
		})
	}
}

func TestSourceItem_EntryCountries(t *testing.T) {
	si := &SourceItem{Countries: []string{"TH", "US"}}
	got := si.EntryCountries()
	if len(got) != 2 || got[0] != "TH" || got[1] != "US" {
		t.Errorf("EntryCountries() = %v, want [TH US]", got)
	}
}

func TestSourceItem_EntryDisabled(t *testing.T) {
	si := &SourceItem{Disabled: true}
	if !si.EntryDisabled() {
		t.Error("EntryDisabled() = false, want true")
	}
}

func TestSourceItem_EntryDetectors(t *testing.T) {
	si := &SourceItem{Detectors: []string{"Simple", "BP"}}
	got := si.EntryDetectors()
	if len(got) != 2 || got[0] != "Simple" {
		t.Errorf("EntryDetectors() = %v, want [Simple BP]", got)
	}
}

// --- ObserveItem.EntryKey ---

func TestObserveItem_EntryKey_FromKey(t *testing.T) {
	oi := &ObserveItem{Key: "my.exness.com"}
	want := "my.exness.com"
	if got := oi.EntryKey(); got != want {
		t.Errorf("EntryKey() = %q, want %q", got, want)
	}
}

func TestObserveItem_EntryKey_ExplicitKey(t *testing.T) {
	oi := &ObserveItem{Key: "deposit"}
	if got := oi.EntryKey(); got != "deposit" {
		t.Errorf("EntryKey() = %q, want %q", got, "deposit")
	}
}

func TestObserveItem_EntryIdent_EqualsEntryKey(t *testing.T) {
	oi := &ObserveItem{Key: "deposit"}
	if oi.EntryIdent() != oi.EntryKey() {
		t.Errorf("EntryIdent() = %q, want EntryKey() = %q", oi.EntryIdent(), oi.EntryKey())
	}
}

func TestObserveItem_EntryObserveCountries(t *testing.T) {
	p := ObserveProbability(0.8)
	oi := &ObserveItem{Countries: ObserveCountries{"TH": &p}}
	got := oi.EntryObserveCountries()
	if len(got) != 1 {
		t.Fatalf("len(EntryObserveCountries()) = %d, want 1", len(got))
	}
	if got["TH"] == nil || *got["TH"] != 0.8 {
		t.Error("EntryObserveCountries()[TH] != 0.8")
	}
}

// --- VerifyItem.EntryKey / EntryIdent ---

func TestVerifyItem_EntryKey_ExplicitKey(t *testing.T) {
	vi := &VerifyItem{Key: "deposit"}
	if got := vi.EntryKey(); got != "deposit" {
		t.Errorf("EntryKey() = %q, want %q", got, "deposit")
	}
}

func TestVerifyItem_EntryKey_FromURI(t *testing.T) {
	vi := &VerifyItem{URI: "https://Domain.COM"}
	want := "https://domain.com"
	if got := vi.EntryKey(); got != want {
		t.Errorf("EntryKey() = %q, want %q", got, want)
	}
}

func TestVerifyItem_EntryIdent_WithCountries(t *testing.T) {
	p := VerifyProbability(0.8)
	vi := &VerifyItem{
		Key: "domain.com",
		Countries: VerifyCountries{
			"US": &VerifyStatus{Probability: &p},
			"TH": &VerifyStatus{Probability: &p},
		},
	}
	got := vi.EntryIdent()
	want := "domain.com [TH,US]" // sorted
	if got != want {
		t.Errorf("EntryIdent() = %q, want %q", got, want)
	}
}

func TestVerifyItem_EntryIdent_NoCountries(t *testing.T) {
	vi := &VerifyItem{Key: "domain.com", Countries: VerifyCountries{}}
	got := vi.EntryIdent()
	want := "domain.com"
	if got != want {
		t.Errorf("EntryIdent() = %q, want %q (no brackets for empty countries)", got, want)
	}
}

func TestVerifyItem_EntryIdent_SingleCountry(t *testing.T) {
	p := VerifyProbability(0.5)
	vi := &VerifyItem{
		Key:       "domain.com",
		Countries: VerifyCountries{"TH": &VerifyStatus{Probability: &p}},
	}
	got := vi.EntryIdent()
	want := "domain.com [TH]"
	if got != want {
		t.Errorf("EntryIdent() = %q, want %q", got, want)
	}
}

func TestVerifyItem_EntryVerifyCountries(t *testing.T) {
	p := VerifyProbability(0.5)
	vi := &VerifyItem{Countries: VerifyCountries{"TH": &VerifyStatus{Probability: &p}}}
	got := vi.EntryVerifyCountries()
	if len(got) != 1 || got["TH"] == nil || *got["TH"].Probability != 0.5 {
		t.Error("EntryVerifyCountries() unexpected")
	}
}
