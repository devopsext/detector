package common

import (
	"bytes"
	"testing"
	"time"
)

// --- NormalizeURI ---

func TestNormalizeURI_ToLower(t *testing.T) {
	got := NormalizeURI("HTTPS://Domain.COM/Path")
	want := "https://domain.com/path"
	if got != want {
		t.Errorf("NormalizeURI() = %q, want %q", got, want)
	}
}

func TestNormalizeURI_Empty(t *testing.T) {
	got := NormalizeURI("")
	if got != "" {
		t.Errorf("NormalizeURI('') = %q, want ''", got)
	}
}

func TestNormalizeURI_AlreadyLower(t *testing.T) {
	got := NormalizeURI("https://domain.com")
	if got != "https://domain.com" {
		t.Errorf("NormalizeURI() = %q, want 'https://domain.com'", got)
	}
}

// --- NormalizeCountry ---

func TestNormalizeCountry_ToUpper(t *testing.T) {
	got := NormalizeCountry("th")
	if got != "TH" {
		t.Errorf("NormalizeCountry('th') = %q, want 'TH'", got)
	}
}

func TestNormalizeCountry_Empty(t *testing.T) {
	got := NormalizeCountry("")
	if got != "" {
		t.Errorf("NormalizeCountry('') = %q, want ''", got)
	}
}

func TestNormalizeCountry_AlreadyUpper(t *testing.T) {
	got := NormalizeCountry("TH")
	if got != "TH" {
		t.Errorf("NormalizeCountry('TH') = %q, want 'TH'", got)
	}
}

// --- URIParse ---

func TestURIParse_WithScheme(t *testing.T) {
	u, err := URIParse("https://domain.com:443/path")
	if err != nil {
		t.Fatalf("URIParse error: %v", err)
	}
	if u == nil {
		t.Fatal("URIParse returned nil")
	}
	if u.Scheme != "https" {
		t.Errorf("Scheme = %q, want 'https'", u.Scheme)
	}
	if u.Port != "443" {
		t.Errorf("Port = %q, want '443'", u.Port)
	}
	if u.Path != "/path" {
		t.Errorf("Path = %q, want '/path'", u.Path)
	}
}

func TestURIParse_NoScheme(t *testing.T) {
	u, err := URIParse("domain.com")
	if err != nil {
		t.Fatalf("URIParse error: %v", err)
	}
	if u == nil {
		t.Fatal("URIParse returned nil for bare domain")
	}
}

func TestURIParse_Empty(t *testing.T) {
	u, err := URIParse("")
	if err != nil {
		t.Fatalf("URIParse('') error: %v", err)
	}
	// Empty string parses without error in Go's url.Parse but result is empty URI
	_ = u
}

// --- Md5 ---

func TestMd5_Consistency(t *testing.T) {
	h1 := Md5([]byte("hello"))
	h2 := Md5([]byte("hello"))
	if !bytes.Equal(h1, h2) {
		t.Error("Md5 should be deterministic")
	}
}

func TestMd5_DifferentInputs(t *testing.T) {
	h1 := Md5([]byte("hello"))
	h2 := Md5([]byte("world"))
	if bytes.Equal(h1, h2) {
		t.Error("Different inputs should produce different hashes")
	}
}

func TestMd5_Empty(t *testing.T) {
	got := Md5([]byte(""))
	if len(got) == 0 {
		t.Error("Md5('') should produce a non-empty hash")
	}
}

func TestMd5_Length(t *testing.T) {
	got := Md5([]byte("test"))
	if len(got) != 16 {
		t.Errorf("Md5 hash length = %d, want 16 bytes", len(got))
	}
}

// --- Duration ---

func TestDuration_ValidString(t *testing.T) {
	d := Duration("5m", 0)
	if d != 5*time.Minute {
		t.Errorf("Duration('5m', 0) = %v, want 5m", d)
	}
}

func TestDuration_InvalidString_ReturnsDefault(t *testing.T) {
	d := Duration("invalid", 10*time.Second)
	if d != 10*time.Second {
		t.Errorf("Duration('invalid', 10s) = %v, want 10s (default)", d)
	}
}

func TestDuration_Empty_ReturnsDefault(t *testing.T) {
	d := Duration("", 30*time.Second)
	if d != 30*time.Second {
		t.Errorf("Duration('', 30s) = %v, want 30s (default)", d)
	}
}

// --- ExtractDomain ---

func TestExtractDomain_WithScheme(t *testing.T) {
	got := ExtractDomain("https://domain.com/path")
	if got != "domain.com" {
		t.Errorf("ExtractDomain() = %q, want 'domain.com'", got)
	}
}

func TestExtractDomain_WithPort(t *testing.T) {
	got := ExtractDomain("https://domain.com:443/path")
	if got != "domain.com" {
		t.Errorf("ExtractDomain() = %q, want 'domain.com'", got)
	}
}

func TestExtractDomain_BareHost(t *testing.T) {
	got := ExtractDomain("domain.com")
	if got != "domain.com" {
		t.Errorf("ExtractDomain() = %q, want 'domain.com'", got)
	}
}

func TestExtractDomain_Empty(t *testing.T) {
	got := ExtractDomain("")
	if got != "unknown" {
		t.Errorf("ExtractDomain('') = %q, want 'unknown'", got)
	}
}

// --- NormalizeCountryForMetrics ---

func TestNormalizeCountryForMetrics_ToLower(t *testing.T) {
	got := NormalizeCountryForMetrics("TH")
	if got != "th" {
		t.Errorf("NormalizeCountryForMetrics('TH') = %q, want 'th'", got)
	}
}

func TestNormalizeCountryForMetrics_Empty(t *testing.T) {
	got := NormalizeCountryForMetrics("")
	if got != "unknown" {
		t.Errorf("NormalizeCountryForMetrics('') = %q, want 'unknown'", got)
	}
}
