package common

import (
	"encoding/json"
	"testing"
)

// --- JSON Serialization ---

func TestSourceItem_JSON_RoundTrip(t *testing.T) {
	resp := &SourceItemResponse{Code: "200", Content: "OK"}
	orig := &SourceItem{
		Key:       "payment",
		URI:       "https://domain.com",
		Disabled:  true,
		Countries: []string{"TH", "US"},
		IPs:       []string{"1.1.1.1"},
		Detectors: []string{"Simple"},
		Response:  resp,
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got SourceItem
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if got.Key != orig.Key {
		t.Errorf("Key = %q, want %q", got.Key, orig.Key)
	}
	if got.URI != orig.URI {
		t.Errorf("URI = %q, want %q", got.URI, orig.URI)
	}
	if got.Disabled != orig.Disabled {
		t.Errorf("Disabled = %v, want %v", got.Disabled, orig.Disabled)
	}
	if len(got.Countries) != 2 || got.Countries[0] != "TH" {
		t.Errorf("Countries = %v, want [TH US]", got.Countries)
	}
	if len(got.IPs) != 1 || got.IPs[0] != "1.1.1.1" {
		t.Errorf("IPs = %v, want [1.1.1.1]", got.IPs)
	}
	if got.Response == nil || got.Response.Code != "200" {
		t.Errorf("Response = %v, want Code=200", got.Response)
	}
}

func TestSourceItem_JSON_OmitEmpty(t *testing.T) {
	si := &SourceItem{URI: "https://domain.com"}
	data, _ := json.Marshal(si)
	s := string(data)

	// Key is empty → should not appear in JSON (omitempty)
	if containsKey(s, "key") {
		t.Error("JSON contains 'key' but it should be omitted when empty")
	}
	// Countries is nil → should not appear
	if containsKey(s, "countries") {
		t.Error("JSON contains 'countries' but it should be omitted when nil")
	}
	// Response is nil → should not appear
	if containsKey(s, "response") {
		t.Error("JSON contains 'response' but it should be omitted when nil")
	}
}

func TestSourceItem_JSON_DisabledFalse(t *testing.T) {
	si := &SourceItem{URI: "https://domain.com", Disabled: false}
	data, _ := json.Marshal(si)
	s := string(data)

	// Disabled has NO omitempty → "disabled":false should be present
	if !containsKey(s, "disabled") {
		t.Error("JSON does not contain 'disabled' — it should be present even when false (no omitempty)")
	}
}

func TestSourceItem_JSON_NilResponse(t *testing.T) {
	si := &SourceItem{URI: "x.com", Response: nil}
	data, _ := json.Marshal(si)
	if containsKey(string(data), "response") {
		t.Error("JSON contains 'response' but it should be omitted when nil")
	}
}

func TestSourceItemResponse_JSON_OmitEmpty(t *testing.T) {
	r := &SourceItemResponse{}
	data, _ := json.Marshal(r)
	s := string(data)
	// Both Code and Content have omitempty
	if s != "{}" {
		t.Errorf("Expected empty JSON object, got %s", s)
	}
}

// helper: checks if JSON string contains a given key
func containsKey(jsonStr, key string) bool {
	var m map[string]interface{}
	json.Unmarshal([]byte(jsonStr), &m)
	_, ok := m[key]
	return ok
}

// --- SourceItems CRUD ---

func TestSourceItems_AddAndItems(t *testing.T) {
	var items SourceItems
	si1 := &SourceItem{Key: "a"}
	si2 := &SourceItem{Key: "b"}
	items.Add(si1, si2)

	got := items.Items()
	if len(got) != 2 {
		t.Fatalf("len(Items()) = %d, want 2", len(got))
	}
}

func TestSourceItems_IsEmpty_True(t *testing.T) {
	var items SourceItems
	if !items.IsEmpty() {
		t.Error("IsEmpty() = false, want true")
	}
}

func TestSourceItems_IsEmpty_False(t *testing.T) {
	var items SourceItems
	items.Add(&SourceItem{Key: "a"})
	if items.IsEmpty() {
		t.Error("IsEmpty() = true, want false")
	}
}

// --- CheckSourceItems ---

func TestCheckSourceItems_FilterNilAndEmpty(t *testing.T) {
	valid := &SourceItem{URI: "https://domain.com"}
	emptyKey := &SourceItem{} // EntryKey() returns ""
	input := []*SourceItem{nil, emptyKey, valid}

	got := CheckSourceItems(input)
	if len(got) != 1 {
		t.Fatalf("CheckSourceItems returned %d items, want 1", len(got))
	}
	if got[0].URI != "https://domain.com" {
		t.Errorf("got URI = %q, want %q", got[0].URI, "https://domain.com")
	}
}

func TestCheckSourceItems_AllNil(t *testing.T) {
	got := CheckSourceItems([]*SourceItem{nil, nil})
	if len(got) != 0 {
		t.Errorf("CheckSourceItems returned %d items, want 0", len(got))
	}
}

func TestCheckSourceItems_WithKey(t *testing.T) {
	items := []*SourceItem{
		{Key: "deposit"},
		{Key: ""},
	}
	got := CheckSourceItems(items)
	if len(got) != 1 || got[0].Key != "deposit" {
		t.Errorf("got %+v, want [deposit]", got)
	}
}

// --- SourceItems.Reduce ---

func TestSourceItems_Reduce_DedupByURI(t *testing.T) {
	var items SourceItems
	items.Add(
		&SourceItem{URI: "https://domain.com", Countries: []string{"TH"}},
		&SourceItem{URI: "https://domain.com", Countries: []string{"US"}},
	)

	r := items.Reduce()
	got := r.Items()
	if len(got) != 1 {
		t.Fatalf("Reduce() produced %d items, want 1", len(got))
	}
}

func TestSourceItems_Reduce_MergeCountries(t *testing.T) {
	var items SourceItems
	items.Add(
		&SourceItem{URI: "https://domain.com", Countries: []string{"TH", "US"}},
		&SourceItem{URI: "https://domain.com", Countries: []string{"TH", "VN"}},
	)

	r := items.Reduce()
	got := r.Items()
	if len(got) != 1 {
		t.Fatalf("Reduce() produced %d items, want 1", len(got))
	}
	countries := got[0].EntryCountries()
	if len(countries) != 3 {
		t.Errorf("countries = %v, want 3 unique countries [TH US VN]", countries)
	}
}

func TestSourceItems_Reduce_MergeIPs(t *testing.T) {
	var items SourceItems
	items.Add(
		&SourceItem{URI: "https://d.com", IPs: []string{"1.1.1.1"}},
		&SourceItem{URI: "https://d.com", IPs: []string{"2.2.2.2"}},
	)

	r := items.Reduce()
	got := r.Items()
	if len(got) != 1 {
		t.Fatalf("Reduce() produced %d items, want 1", len(got))
	}
	ep, ok := got[0].(*SourceItem)
	if !ok {
		t.Fatal("result is not *SourceItem")
	}
	if len(ep.IPs) != 2 {
		t.Errorf("IPs = %v, want 2 IPs", ep.IPs)
	}
}

func TestSourceItems_Reduce_MergeIPs_Dedup(t *testing.T) {
	var items SourceItems
	items.Add(
		&SourceItem{URI: "https://d.com", IPs: []string{"1.1.1.1"}},
		&SourceItem{URI: "https://d.com", IPs: []string{"1.1.1.1", "2.2.2.2"}},
	)

	r := items.Reduce()
	ep := r.Items()[0].(*SourceItem)
	if len(ep.IPs) != 2 {
		t.Errorf("IPs = %v, want 2 unique IPs (dedup)", ep.IPs)
	}
}

func TestSourceItems_Reduce_MergeResponse_MultipleCodes(t *testing.T) {
	var items SourceItems
	items.Add(
		&SourceItem{URI: "https://d.com", Response: &SourceItemResponse{Code: "200"}},
		&SourceItem{URI: "https://d.com", Response: &SourceItemResponse{Code: "404"}},
	)

	r := items.Reduce()
	ep := r.Items()[0].(*SourceItem)
	if ep.Response == nil {
		t.Fatal("Response is nil")
	}
	if ep.Response.Code != "200|404" && ep.Response.Code != "404|200" {
		t.Errorf("Response.Code = %q, want '200|404' or '404|200'", ep.Response.Code)
	}
}

func TestSourceItems_Reduce_MergeResponse_DedupCodes(t *testing.T) {
	var items SourceItems
	items.Add(
		&SourceItem{URI: "https://d.com", Response: &SourceItemResponse{Code: "200"}},
		&SourceItem{URI: "https://d.com", Response: &SourceItemResponse{Code: "200"}},
	)

	r := items.Reduce()
	ep := r.Items()[0].(*SourceItem)
	if ep.Response.Code != "200" {
		t.Errorf("Response.Code = %q, want '200' (dedup)", ep.Response.Code)
	}
}

func TestSourceItems_Reduce_GroupByExplicitKey(t *testing.T) {
	var items SourceItems
	items.Add(
		&SourceItem{Key: "payment", Countries: []string{"TH"}},
		&SourceItem{Key: "withdraw", Countries: []string{"US"}},
	)

	r := items.Reduce()
	if len(r.Items()) != 2 {
		t.Errorf("Reduce() produced %d items, want 2 (different keys)", len(r.Items()))
	}
}

func TestSourceItems_Reduce_NilEntry(t *testing.T) {
	var items SourceItems
	items.Add(nil, &SourceItem{Key: "a"})

	r := items.Reduce()
	if len(r.Items()) != 1 {
		t.Errorf("Reduce() produced %d items, want 1 (nil skipped)", len(r.Items()))
	}
}

func TestSourceItems_Reduce_Empty(t *testing.T) {
	var items SourceItems
	r := items.Reduce()
	if !r.IsEmpty() {
		t.Error("Reduce() of empty should be empty")
	}
}

// --- SourceItems.Clone ---

func TestSourceItems_Clone(t *testing.T) {
	var items SourceItems
	orig := &SourceItem{
		Key:       "a",
		URI:       "https://d.com",
		Disabled:  true,
		Countries: []string{"TH"},
		IPs:       []string{"1.1.1.1"},
		Response:  &SourceItemResponse{Code: "200", Content: "OK"},
	}

	cloned := items.Clone(orig)

	if cloned.Key != orig.Key || cloned.URI != orig.URI || cloned.Disabled != orig.Disabled {
		t.Error("Clone basic fields mismatch")
	}
	if cloned.Response == nil || cloned.Response.Code != "200" {
		t.Error("Clone Response mismatch")
	}

	// Modify the clone and verify original is unchanged
	cloned.Key = "b"
	cloned.Response.Code = "500"
	if orig.Key != "a" {
		t.Error("Modifying clone changed original Key")
	}
	if orig.Response.Code != "200" {
		t.Error("Modifying clone changed original Response.Code")
	}
}
